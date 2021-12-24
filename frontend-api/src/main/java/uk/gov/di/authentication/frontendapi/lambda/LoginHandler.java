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
import uk.gov.di.authentication.shared.conditions.MfaHelper;
import uk.gov.di.authentication.shared.conditions.TermsAndConditionsHelper;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
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
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.LOG_IN_SUCCESS;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class LoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LoginHandler.class);
    private final CodeStorageService codeStorageService;
    private final UserMigrationService userMigrationService;
    private final AuditService auditService;

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
            Optional<UserProfile> userProfileMaybe =
                    authenticationService.getUserProfileByEmailMaybe(request.getEmail());
            if (userProfileMaybe.isEmpty()) {

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

            UserProfile userProfile = userProfileMaybe.get();

            int incorrectPasswordCount =
                    codeStorageService.getIncorrectPasswordCount(request.getEmail());

            if (incorrectPasswordCount >= configurationService.getMaxPasswordRetries()) {
                LOG.info("User has exceeded max password retries");

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

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1028);
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

            CredentialTrustLevel credentialTrustLevel =
                    userContext
                            .getClientSession()
                            .getEffectiveVectorOfTrust()
                            .getCredentialTrustLevel();

            Session session = userContext.getSession();
            if (credentialTrustLevel.equals(CredentialTrustLevel.LOW_LEVEL)) {
                session.setCurrentCredentialStrength(credentialTrustLevel);
            }

            sessionService.save(session.setNewAccount(EXISTING));

            var isMfaRequired =
                    MfaHelper.mfaRequired(userContext.getClientSession().getAuthRequestParams());

            boolean isPhoneNumberVerified = userProfile.isPhoneNumberVerified();
            String redactedPhoneNumber = null;
            if (isPhoneNumberVerified) {
                redactedPhoneNumber =
                        RedactPhoneNumberHelper.redactPhoneNumber(userProfile.getPhoneNumber());
            }
            boolean termsAndConditionsAccepted;
            if (userProfile.getTermsAndConditions() == null) {
                termsAndConditionsAccepted = false;
            } else {
                termsAndConditionsAccepted =
                        TermsAndConditionsHelper.hasTermsAndConditionsBeenAccepted(
                                userProfile.getTermsAndConditions(),
                                configurationService.getTermsAndConditionsVersion());
            }
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
                    200,
                    new LoginResponse(
                            redactedPhoneNumber,
                            isMfaRequired,
                            isPhoneNumberVerified,
                            termsAndConditionsAccepted));
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
