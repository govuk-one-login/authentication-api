package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequestHandlerResponse;
import uk.gov.di.authentication.frontendapi.exceptions.SerializationException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestClientHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.getLastDigitsOfPhoneNumber;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class ResetPasswordRequestHandler extends BaseFrontendHandler<ResetPasswordRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(ResetPasswordRequestHandler.class);

    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            AuthSessionService authSessionService) {
        super(
                ResetPasswordRequest.class,
                configurationService,
                sessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
    }

    public ResetPasswordRequestHandler() {
        this(ConfigurationService.getInstance());
    }

    public ResetPasswordRequestHandler(ConfigurationService configurationService) {
        super(ResetPasswordRequest.class, configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(ResetPasswordRequest.class, configurationService, redis);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
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
            ResetPasswordRequest request,
            UserContext userContext) {
        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

        LOG.info("Processing request");
        try {
            if (Objects.isNull(userContext.getAuthSession().getEmailAddress())
                    || !userContext.getAuthSession().validateSession(request.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }

            var userIsAlreadyLockedOutOfPasswordReset =
                    hasUserExceededMaxAllowedRequests(request.getEmail(), userContext);

            if (userIsAlreadyLockedOutOfPasswordReset.isPresent()) {
                return generateApiGatewayProxyErrorResponse(
                        400, userIsAlreadyLockedOutOfPasswordReset.get());
            }

            var isTestClient =
                    TestClientHelper.isTestClientWithAllowedEmail(
                            userContext, configurationService);

            emitPasswordResetRequestedAuditEvent(input, request, userContext, isTestClient);

            authSessionService.updateSession(
                    userContext.getAuthSession().incrementPasswordResetCount());

            var userIsNewlyLockedOutOfPasswordReset =
                    hasUserExceededMaxAllowedRequests(request.getEmail(), userContext);

            if (userIsNewlyLockedOutOfPasswordReset.isPresent()) {
                lockUserOutOfPasswordReset(userContext);
                return generateApiGatewayProxyErrorResponse(
                        400, userIsNewlyLockedOutOfPasswordReset.get());
            }

            authSessionService.updateSession(
                    userContext
                            .getAuthSession()
                            .withResetPasswordState(AuthSessionItem.ResetPasswordState.ATTEMPTED));

            return processPasswordResetRequest(request, userContext, isTestClient);
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private void lockUserOutOfPasswordReset(UserContext userContext) {
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
        var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
        LOG.info("Setting block for email as user has requested too many OTPs");
        codeStorageService.saveBlockedForEmail(
                userContext.getAuthSession().getEmailAddress(),
                codeRequestBlockedKeyPrefix,
                configurationService.getLockoutDuration());
        authSessionService.updateSession(userContext.getAuthSession().resetPasswordResetCount());
    }

    private void emitPasswordResetRequestedAuditEvent(
            APIGatewayProxyRequestEvent input,
            ResetPasswordRequest request,
            UserContext userContext,
            boolean isTestClient) {
        int passwordResetCounter = userContext.getAuthSession().getPasswordResetCount();
        var passwordResetCounterPair = pair("passwordResetCounter", passwordResetCounter);
        var passwordResetTypePair =
                request.isWithinForcedPasswordResetJourney()
                        ? pair(
                                "passwordResetType",
                                PasswordResetType.FORCED_INTERVENTION_PASSWORD_RESET)
                        : pair("passwordResetType", PasswordResetType.USER_FORGOTTEN_PASSWORD);

        LOG.info("passwordResetType: {}", passwordResetTypePair);

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        authenticationService.getPhoneNumber(request.getEmail()).orElse(null),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
        var eventName =
                isTestClient
                        ? AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT
                        : AUTH_PASSWORD_RESET_REQUESTED;

        auditService.submitAuditEvent(
                eventName, auditContext, passwordResetCounterPair, passwordResetTypePair);
    }

    private APIGatewayProxyResponseEvent processPasswordResetRequest(
            ResetPasswordRequest resetPasswordRequest,
            UserContext userContext,
            boolean isTestClient) {
        var code =
                codeStorageService
                        .getOtpCode(resetPasswordRequest.getEmail(), RESET_PASSWORD_WITH_CODE)
                        .orElseGet(
                                () -> {
                                    var newCode = codeGeneratorService.sixDigitCode();
                                    codeStorageService.saveOtpCode(
                                            resetPasswordRequest.getEmail(),
                                            newCode,
                                            configurationService.getDefaultOtpCodeExpiry(),
                                            RESET_PASSWORD_WITH_CODE);
                                    return newCode;
                                });

        if (isTestClient) {
            LOG.info("User is a TestClient so will NOT place message on queue");
        } else {
            LOG.info("Placing message on queue");
            var notifyRequest =
                    new NotifyRequest(
                            resetPasswordRequest.getEmail(),
                            RESET_PASSWORD_WITH_CODE,
                            code,
                            userContext.getUserLanguage(),
                            userContext.getAuthSession().getSessionId(),
                            userContext.getClientSessionId());
            sqsClient.send(serialiseNotifyRequest(notifyRequest));
            LOG.info(
                    "{} EMAIL placed on queue with reference: {}",
                    notifyRequest.getNotificationType(),
                    notifyRequest.getUniqueNotificationReference());
        }

        LOG.info("Successfully processed request");
        var credentialTrustLevel = userContext.getAuthSession().getRequestedCredentialStrength();
        var maybeResponse =
                generateResponseWithMfaDetail(resetPasswordRequest, credentialTrustLevel);
        if (maybeResponse.isPresent()) {
            try {
                return generateApiGatewayProxyResponse(200, maybeResponse.get());
            } catch (JsonException e) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
            }
        } else {
            LOG.error("Could not find user profile for reset password request");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }
    }

    Optional<ResetPasswordRequestHandlerResponse> generateResponseWithMfaDetail(
            ResetPasswordRequest resetPasswordRequest, CredentialTrustLevel credentialTrustLevel) {
        return authenticationService
                .getUserProfileByEmailMaybe(resetPasswordRequest.getEmail())
                .map(
                        userProfile -> {
                            var userMfaDetail =
                                    getUserMFADetail(
                                            credentialTrustLevel,
                                            authenticationService.getUserCredentialsFromEmail(
                                                    resetPasswordRequest.getEmail()),
                                            userProfile);

                            return new ResetPasswordRequestHandlerResponse(
                                    userMfaDetail.mfaMethodType(),
                                    getLastDigitsOfPhoneNumber(userMfaDetail));
                        });
    }

    private Optional<ErrorResponse> hasUserExceededMaxAllowedRequests(
            String email, UserContext userContext) {
        LOG.info("Validating Password Reset Count");
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
        var codeRequestCount = userContext.getAuthSession().getPasswordResetCount();
        var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
        var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        if (codeRequestCount >= configurationService.getCodeMaxRetries()) {
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        if (codeStorageService.isBlockedForEmail(email, codeRequestBlockedKeyPrefix)) {
            LOG.info("Code is blocked for email as user has requested too many OTPs");
            return Optional.of(ErrorResponse.ERROR_1023);
        }
        if (codeStorageService.isBlockedForEmail(email, codeAttemptsBlockedKeyPrefix)) {
            LOG.info("Code is blocked for email as user has entered too many invalid OTPs");
            return Optional.of(ErrorResponse.ERROR_1039);
        }
        return Optional.empty();
    }

    private String serialiseNotifyRequest(Object request) {
        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonException e) {
            LOG.error("Unexpected exception when serializing Notify request");
            throw new SerializationException(
                    "Unexpected exception when serializing Notify request");
        }
    }
}
