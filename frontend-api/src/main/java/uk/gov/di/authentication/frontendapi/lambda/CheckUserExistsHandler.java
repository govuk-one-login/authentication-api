package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.entity.LockoutInformation;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;
import java.util.stream.Stream;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.getLastDigitsOfPhoneNumber;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckUserExistsHandler extends BaseFrontendHandler<CheckUserExistsRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckUserExistsHandler.class);
    private final AuditService auditService;
    private final CodeStorageService codeStorageService;

    public CheckUserExistsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthSessionService authSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CodeStorageService codeStorageService) {
        super(
                CheckUserExistsRequest.class,
                configurationService,
                sessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
        this.codeStorageService = codeStorageService;
    }

    public CheckUserExistsHandler() {
        this(ConfigurationService.getInstance());
    }

    public CheckUserExistsHandler(ConfigurationService configurationService) {
        super(CheckUserExistsRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    public CheckUserExistsHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(CheckUserExistsRequest.class, configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            CheckUserExistsRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

        try {
            LOG.info("Processing request");

            String emailAddress = request.getEmail().toLowerCase();
            Optional<ErrorResponse> errorResponse =
                    ValidationHelper.validateEmailAddress(emailAddress);
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            AuditService.UNKNOWN,
                            emailAddress,
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            persistentSessionId);

            if (errorResponse.isPresent()) {

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CHECK_USER_INVALID_EMAIL, auditContext);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            var userProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
            var userExists = userProfile.isPresent();
            userContext.getAuthSession().setEmailAddress(emailAddress);

            if (codeStorageService.isBlockedForEmail(
                    emailAddress,
                    CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET)) {
                LOG.info("User account is locked");
                authSessionService.updateSession(userContext.getAuthSession());

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        auditContext,
                        pair(
                                "number_of_attempts_user_allowed_to_login",
                                configurationService.getMaxPasswordRetries()));

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1045);
            }

            AuditableEvent auditableEvent;
            var rpPairwiseId = AuditService.UNKNOWN;
            var userMfaDetail = UserMfaDetail.noMfa();

            AuthSessionItem authSession = userContext.getAuthSession();

            if (userExists) {
                auditableEvent = FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL;
                rpPairwiseId =
                        ClientSubjectHelper.getSubject(
                                        userProfile.get(),
                                        userContext.getClient().get(),
                                        userContext.getAuthSession(),
                                        authenticationService,
                                        configurationService.getInternalSectorUri())
                                .getValue();
                var internalCommonSubjectId =
                        ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile.get(),
                                        configurationService.getInternalSectorUri(),
                                        authenticationService)
                                .getValue();

                LOG.info("Setting internal common subject identifier in user session");

                authSession.setInternalCommonSubjectId(internalCommonSubjectId);
                var userCredentials =
                        authenticationService.getUserCredentialsFromEmail(emailAddress);
                userMfaDetail =
                        getUserMFADetail(
                                authSession.getRequestedCredentialStrength(),
                                userCredentials,
                                userProfile.get());
                auditContext = auditContext.withSubjectId(internalCommonSubjectId);
            } else {
                authSession.setInternalCommonSubjectId(null);
                auditableEvent = FrontendAuditableEvent.AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
            }

            auditService.submitAuditEvent(
                    auditableEvent, auditContext, pair("rpPairwiseId", rpPairwiseId));

            var lockoutInformation =
                    Stream.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA)
                            .map(
                                    journeyType -> {
                                        var ttl =
                                                codeStorageService.getMfaCodeBlockTimeToLive(
                                                        emailAddress,
                                                        MFAMethodType.AUTH_APP,
                                                        journeyType);
                                        return new LockoutInformation(
                                                "codeBlock",
                                                MFAMethodType.AUTH_APP,
                                                ttl,
                                                journeyType);
                                    })
                            .filter(info -> info.lockTTL() > 0)
                            .toList();

            CheckUserExistsResponse checkUserExistsResponse =
                    new CheckUserExistsResponse(
                            emailAddress,
                            userExists,
                            userMfaDetail.mfaMethodType(),
                            getLastDigitsOfPhoneNumber(userMfaDetail),
                            lockoutInformation);
            authSessionService.updateSession(authSession);

            LOG.info("Successfully processed request");

            return generateApiGatewayProxyResponse(200, checkUserExistsResponse);

        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
