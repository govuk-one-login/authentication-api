package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.DecisionErrorHttpMapper;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequestHandlerResponse;
import uk.gov.di.authentication.frontendapi.exceptions.SerializationException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TemporarilyLockedOutData;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.getLastDigitsOfPhoneNumber;
import static uk.gov.di.authentication.frontendapi.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ResetPasswordRequestHandler extends BaseFrontendHandler<ResetPasswordRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(ResetPasswordRequestHandler.class);

    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final MFAMethodsService mfaMethodsService;
    private final PermissionDecisionManager permissionDecisionManager;
    private final UserActionsManager userActionsManager;
    private final TestUserHelper testUserHelper;

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            AuthSessionService authSessionService,
            MFAMethodsService mfaMethodsService,
            PermissionDecisionManager permissionDecisionManager,
            UserActionsManager userActionsManager,
            TestUserHelper testUserHelper) {
        super(
                ResetPasswordRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaMethodsService = mfaMethodsService;
        this.permissionDecisionManager = permissionDecisionManager;
        this.userActionsManager = userActionsManager;
        this.testUserHelper = testUserHelper;
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
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.permissionDecisionManager =
                new PermissionDecisionManager(configurationService, codeStorageService);
        this.userActionsManager =
                new UserActionsManager(
                        configurationService, codeStorageService, authSessionService);
        this.testUserHelper = new TestUserHelper(configurationService);
    }

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(ResetPasswordRequest.class, configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.permissionDecisionManager =
                new PermissionDecisionManager(configurationService, codeStorageService);
        this.userActionsManager =
                new UserActionsManager(
                        configurationService, codeStorageService, authSessionService);
        this.testUserHelper = new TestUserHelper(configurationService);
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
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.SESSION_ID_MISSING);
            }

            var permissionContext =
                    PermissionContext.builder()
                            .withInternalSubjectId(
                                    userContext.getAuthSession().getInternalCommonSubjectId())
                            .withEmailAddress(request.getEmail())
                            .withAuthSessionItem(userContext.getAuthSession())
                            .build();

            var permissionCheckResult = checkUserPermissions(request.getEmail(), userContext);
            if (permissionCheckResult.isFailure()) {
                return permissionCheckResult.getFailure();
            }

            var isTestClient = testUserHelper.isTestJourney(userContext);

            emitPasswordResetRequestedAuditEvent(input, request, userContext, isTestClient);

            // Call the action to increment the count
            userActionsManager.sentEmailOtpNotification(
                    JourneyType.PASSWORD_RESET, permissionContext);

            authSessionService.updateSession(
                    userContext
                            .getAuthSession()
                            .withResetPasswordState(AuthSessionItem.ResetPasswordState.ATTEMPTED));

            return processPasswordResetRequest(request, userContext, isTestClient);
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        }
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

        var retrieveMfaMethods = mfaMethodsService.getMfaMethods(resetPasswordRequest.getEmail());
        if (retrieveMfaMethods.isFailure()) {
            return switch (retrieveMfaMethods.getFailure()) {
                case UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP -> generateApiGatewayProxyErrorResponse(
                        500, ErrorResponse.AUTH_APP_MFA_ID_ERROR);
                case USER_DOES_NOT_HAVE_ACCOUNT -> {
                    LOG.error("Could not find user profile for reset password request");
                    yield generateApiGatewayProxyErrorResponse(404, ErrorResponse.USER_NOT_FOUND);
                }
                case UNKNOWN_MFA_IDENTIFIER -> {
                    yield generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.INVALID_MFA_METHOD);
                }
            };
        }

        var retrievedMfaMethods = retrieveMfaMethods.getSuccess();

        var defaultMfaMethod =
                MFAMethodsService.getMfaMethodOrDefaultMfaMethod(retrievedMfaMethods, null, null);
        String defaultMfaType = defaultMfaMethod.map(MFAMethod::getMfaMethodType).orElse(null);
        String defaultMfaPhoneNumber =
                defaultMfaType != null
                                && MFAMethodType.valueOf(defaultMfaType).equals(MFAMethodType.SMS)
                        ? defaultMfaMethod.map(MFAMethod::getDestination).orElse(null)
                        : null;

        var maybeMfaMethodResponses = convertMfaMethodsToMfaMethodResponse(retrievedMfaMethods);
        if (maybeMfaMethodResponses.isFailure()) {
            LOG.error(maybeMfaMethodResponses.getFailure());
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR);
        }

        var mfaMethodResponses = maybeMfaMethodResponses.getSuccess();

        try {
            return generateApiGatewayProxyResponse(
                    200,
                    new ResetPasswordRequestHandlerResponse(
                            defaultMfaType != null ? MFAMethodType.valueOf(defaultMfaType) : null,
                            mfaMethodResponses,
                            defaultMfaPhoneNumber != null
                                    ? getLastDigitsOfPhoneNumber(defaultMfaPhoneNumber)
                                    : null));
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }

    private Result<APIGatewayProxyResponseEvent, Void> checkUserPermissions(
            String email, UserContext userContext) {
        var permissionContext =
                PermissionContext.builder()
                        .withInternalSubjectId(
                                userContext.getAuthSession().getInternalCommonSubjectId())
                        .withEmailAddress(email)
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();

        var canSendResult =
                permissionDecisionManager.canSendEmailOtpNotification(
                        JourneyType.PASSWORD_RESET,
                        permissionContext,
                        permitted -> (Result<APIGatewayProxyResponseEvent, Void>) null,
                        lockedOut -> handleTemporarilyLockedOut(lockedOut, permissionContext));

        if (canSendResult.isFailure()) {
            return Result.failure(
                    DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(
                            canSendResult.getFailure()));
        }

        var lockoutResult = canSendResult.getSuccess();
        if (lockoutResult != null && lockoutResult.isFailure()) {
            return lockoutResult;
        }

        var userIsAlreadyLockedOutOfPasswordReset =
                hasUserExceededMaxAllowedRequests(email, userContext);
        if (userIsAlreadyLockedOutOfPasswordReset.isPresent()) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(
                            400, userIsAlreadyLockedOutOfPasswordReset.get()));
        }

        return Result.success(null);
    }

    private Result<APIGatewayProxyResponseEvent, Void> handleTemporarilyLockedOut(
            TemporarilyLockedOutData lockedOut, PermissionContext permissionContext) {
        if (lockedOut.forbiddenReason()
                == ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT) {
            userActionsManager.sentEmailOtpNotification(
                    JourneyType.PASSWORD_RESET, permissionContext);
            var errorResponse =
                    lockedOut.isFirstTimeLimit()
                            ? ErrorResponse.TOO_MANY_PW_RESET_REQUESTS
                            : ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST;
            return Result.failure(generateApiGatewayProxyErrorResponse(400, errorResponse));
        }
        return Result.success(null);
    }

    private Optional<ErrorResponse> hasUserExceededMaxAllowedRequests(
            String email, UserContext userContext) {
        LOG.info("Validating Password Reset Count");
        var permissionContext =
                PermissionContext.builder()
                        .withInternalSubjectId(
                                userContext.getAuthSession().getInternalCommonSubjectId())
                        .withEmailAddress(email)
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();

        var canSendResult =
                permissionDecisionManager.<Optional<ErrorResponse>>canSendEmailOtpNotification(
                        JourneyType.PASSWORD_RESET,
                        permissionContext,
                        permitted -> Optional.empty(),
                        lockedOut -> {
                            if (lockedOut.forbiddenReason()
                                    == ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST) {
                                LOG.info(
                                        "Code is blocked for email as user has requested too many OTPs");
                                return Optional.of(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST);
                            } else if (lockedOut.forbiddenReason()
                                    == ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT) {
                                return lockedOut.isFirstTimeLimit()
                                        ? Optional.of(ErrorResponse.TOO_MANY_PW_RESET_REQUESTS)
                                        : Optional.of(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST);
                            }
                            return Optional.empty();
                        });

        if (canSendResult.isFailure()) {
            LOG.error("Decision error: {}", canSendResult.getFailure());
            return Optional.empty();
        }

        if (canSendResult.getSuccess().isPresent()) {
            return canSendResult.getSuccess();
        }

        var canVerifyResult =
                permissionDecisionManager.<Optional<ErrorResponse>>canVerifyEmailOtp(
                        JourneyType.PASSWORD_RESET,
                        permissionContext,
                        permitted -> Optional.empty(),
                        lockedOut -> {
                            LOG.info(
                                    "Code is blocked for email as user has entered too many invalid OTPs");
                            return Optional.of(
                                    ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED);
                        });

        if (canVerifyResult.isFailure()) {
            LOG.error("Decision error: {}", canVerifyResult.getFailure());
            return Optional.empty();
        }

        return canVerifyResult.getSuccess();
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
