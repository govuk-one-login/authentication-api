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
            AuthSessionService authSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CodeStorageService codeStorageService) {
        super(
                CheckUserExistsRequest.class,
                configurationService,
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
        super(CheckUserExistsRequest.class, configurationService);
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
            var internalCommonSubjectId =
                    userExists
                            ? ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                            userProfile.get(),
                                            configurationService.getInternalSectorUri(),
                                            authenticationService)
                                    .getValue()
                            : AuditService.UNKNOWN;
            userContext.getAuthSession().setEmailAddress(emailAddress);

            // Log all Redis keys for this user
            String hashedEmail = uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String(emailAddress);
            LOG.info("Hashed email for Redis keys: {}", hashedEmail);
            
            try {
                // Get all Redis keys for this user
                java.util.List<String> allUserKeys = codeStorageService.getRedisConnectionService().scanKeys("*" + hashedEmail);
                LOG.info("All Redis keys for user {}: {}", emailAddress, allUserKeys);
                
                // Get values for each key
                for (String key : allUserKeys) {
                    String value = codeStorageService.getRedisConnectionService().getValue(key);
                    LOG.info("Redis key: {}, value: {}", key, value);
                }
            } catch (Exception e) {
                LOG.error("Error scanning Redis keys for user: {}", emailAddress, e);
            }
            
            // Check for password reset block
            String passwordResetBlockPrefix = CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET;
            LOG.info("Checking if user is blocked with prefix: {}, email: {}", passwordResetBlockPrefix, emailAddress);
            boolean isPasswordResetBlocked = codeStorageService.isBlockedForEmail(emailAddress, passwordResetBlockPrefix);
            LOG.info("User blocked with PASSWORD_RESET prefix: {}", isPasswordResetBlocked);
            
            // Check for SMS sign-in block
            String smsSignInBlockPrefix = CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX + "SMS_SIGN_IN";
            LOG.info("Checking if user is blocked with prefix: {}, email: {}", smsSignInBlockPrefix, emailAddress);
            boolean isSmsSignInBlocked = codeStorageService.isBlockedForEmail(emailAddress, smsSignInBlockPrefix);
            LOG.info("User blocked with SMS_SIGN_IN prefix: {}", isSmsSignInBlocked);
            
            // Check for AUTH_APP sign-in block
            String authAppSignInBlockPrefix = CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX + "AUTH_APP_SIGN_IN";
            LOG.info("Checking if user is blocked with prefix: {}, email: {}", authAppSignInBlockPrefix, emailAddress);
            boolean isAuthAppSignInBlocked = codeStorageService.isBlockedForEmail(emailAddress, authAppSignInBlockPrefix);
            LOG.info("User blocked with AUTH_APP_SIGN_IN prefix: {}", isAuthAppSignInBlocked);
            
            if (isPasswordResetBlocked || isSmsSignInBlocked || isAuthAppSignInBlocked) {
                LOG.info("User account is locked. Password reset blocked: {}, SMS sign-in blocked: {}, AUTH_APP sign-in blocked: {}", 
                        isPasswordResetBlocked, isSmsSignInBlocked, isAuthAppSignInBlocked);
                auditContext = auditContext.withSubjectId(internalCommonSubjectId);
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
