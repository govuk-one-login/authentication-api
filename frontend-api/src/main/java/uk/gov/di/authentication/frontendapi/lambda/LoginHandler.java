package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.helpers.RedactPhoneNumberHelper;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Objects;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.LOG_IN_SUCCESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.ACCOUNT_LOCK_EXPIRED;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class LoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LoginHandler.class);
    private final CodeStorageService codeStorageService;
    private final UserMigrationService userMigrationService;
    private final AuditService auditService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public LoginHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthenticationService authenticationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            CodeStorageService codeStorageService,
            UserMigrationService userMigrationService,
            AuditService auditService) {
        super(
                LoginRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.userMigrationService = userMigrationService;
        this.auditService = auditService;
    }

    public LoginHandler(ConfigurationService configurationService) {
        super(LoginRequest.class, configurationService);
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.userMigrationService =
                new UserMigrationService(
                        new DynamoService(configurationService), configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public LoginHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            LoginRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession().getSessionId());

        LOG.info("Request received");
        try {
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            UserProfile userProfile =
                    authenticationService.getUserProfileByEmail(request.getEmail());
            if (Objects.isNull(userProfile)) {
                LOG.error("The user does not have an account");

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.NO_ACCOUNT_WITH_EMAIL,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
            }

            SessionState currentState = userContext.getSession().getState();
            int incorrectPasswordCount =
                    codeStorageService.getIncorrectPasswordCount(request.getEmail());

            if (incorrectPasswordCount >= configurationService.getMaxPasswordRetries()) {
                LOG.info("User has exceeded max password retries");
                var nextState =
                        stateMachine.transition(
                                userContext.getSession().getState(),
                                USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                userContext);

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        userProfile.getPhoneNumber(),
                        persistentSessionId);

                sessionService.save(userContext.getSession().setState(nextState));
                return generateApiGatewayProxyResponse(
                        200, new LoginResponse(null, userContext.getSession().getState()));
            }

            if (incorrectPasswordCount == 0
                    && currentState.equals(SessionState.ACCOUNT_TEMPORARILY_LOCKED)) {
                var nextState =
                        stateMachine.transition(
                                userContext.getSession().getState(),
                                ACCOUNT_LOCK_EXPIRED,
                                userContext);
                sessionService.save(userContext.getSession().setState(nextState));
            }

            boolean userIsAMigratedUser =
                    userMigrationService.userHasBeenPartlyMigrated(
                            userProfile.getLegacySubjectID(), request.getEmail());
            boolean hasValidCredentials;
            if (userIsAMigratedUser) {
                LOG.info("Processing migrated user");
                hasValidCredentials =
                        userMigrationService.processMigratedUser(
                                request.getEmail(), request.getPassword());
            } else {
                hasValidCredentials =
                        authenticationService.login(request.getEmail(), request.getPassword());
            }

            if (!hasValidCredentials) {
                codeStorageService.increaseIncorrectPasswordCount(request.getEmail());
                LOG.info("Invalid login credentials entered");

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CREDENTIALS,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1008);
            }

            if (incorrectPasswordCount != 0) {
                codeStorageService.deleteIncorrectPasswordCount(request.getEmail());
            }

            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(),
                            USER_ENTERED_VALID_CREDENTIALS,
                            userContext);

            CredentialTrustLevel credentialTrustLevel =
                    userContext
                            .getClientSession()
                            .getEffectiveVectorOfTrust()
                            .getCredentialTrustLevel();
            Session session = userContext.getSession().setState(nextState);
            if (credentialTrustLevel.equals(CredentialTrustLevel.LOW_LEVEL)) {
                session.setCurrentCredentialStrength(credentialTrustLevel);
            }
            sessionService.save(session);

            if (nextState.equals(TWO_FACTOR_REQUIRED)) {
                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(userContext.getSession().getState()));
            }
            String phoneNumber = userProfile.getPhoneNumber();

            String concatPhoneNumber = RedactPhoneNumberHelper.redactPhoneNumber(phoneNumber);

            LOG.info("User has successfully logged in");

            auditService.submitAuditEvent(
                    LOG_IN_SUCCESS,
                    context.getAwsRequestId(),
                    session.getSessionId(),
                    AuditService.UNKNOWN,
                    userProfile.getSubjectID(),
                    userProfile.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    userProfile.getPhoneNumber(),
                    persistentSessionId);

            return generateApiGatewayProxyResponse(
                    200, new LoginResponse(concatPhoneNumber, userContext.getSession().getState()));
        } catch (JsonProcessingException e) {
            LOG.error("Request is missing parameters");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
