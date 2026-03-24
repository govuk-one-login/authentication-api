package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.errormapper.DecisionErrorHttpMapper;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
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
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_MFA_MISMATCHED_EMAIL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_MFA_MISSING_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.EMAIL_HAS_NO_USER_PROFILE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.PHONE_NUMBER_NOT_REGISTERED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.REQUEST_MISSING_PARAMS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.SESSION_ID_MISSING;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.TOO_MANY_MFA_OTPS_SENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.mfa.MFAMethodsService.getMfaMethodOrDefaultMfaMethod;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT;

public class MfaHandler extends BaseFrontendHandler<MfaRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MfaHandler.class);

    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final AwsSqsClient sqsClient;
    private final MFAMethodsService mfaMethodsService;
    private final TestUserHelper testUserHelper;
    private final PermissionDecisionManager permissionDecisionManager;
    private final UserActionsManager userActionsManager;

    public MfaHandler(
            ConfigurationService configurationService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuthenticationService authenticationService,
            AuditService auditService,
            AwsSqsClient sqsClient,
            AuthSessionService authSessionService,
            MFAMethodsService mfaMethodsService,
            TestUserHelper testUserHelper,
            PermissionDecisionManager permissionDecisionManager,
            UserActionsManager userActionsManager) {
        super(MfaRequest.class, configurationService, authenticationService, authSessionService);
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.sqsClient = sqsClient;
        this.mfaMethodsService = mfaMethodsService;
        this.testUserHelper = testUserHelper;
        this.permissionDecisionManager = permissionDecisionManager;
        this.userActionsManager = userActionsManager;
    }

    public MfaHandler(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        super(MfaRequest.class, configurationService);
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(configurationService, redisConnectionService);
        this.auditService = new AuditService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.testUserHelper = new TestUserHelper(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
        this.userActionsManager = new UserActionsManager(configurationService);
    }

    public MfaHandler() {
        super(MfaRequest.class, ConfigurationService.getInstance());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.testUserHelper = new TestUserHelper(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
        this.userActionsManager = new UserActionsManager(configurationService);
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
            MfaRequest request,
            UserContext userContext) {
        try {
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

            attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

            LOG.info("MfaHandler received request");

            String email = request.getEmail().toLowerCase(Locale.ROOT);
            JourneyType journeyType =
                    request.getJourneyType() != null
                            ? request.getJourneyType()
                            : JourneyType.SIGN_IN;

            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            userContext.getAuthSession().getInternalCommonSubjectId(),
                            email,
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            persistentSessionId);

            auditContext =
                    auditContext.withMetadataItem(
                            pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, journeyType));
            auditContext =
                    auditContext.withMetadataItem(pair("mfa-type", MFAMethodType.SMS.getValue()));

            CodeRequestType.SupportedCodeType supportedCodeType =
                    CodeRequestType.SupportedCodeType.getFromMfaMethodType(
                            NotificationType.MFA_SMS.getMfaMethodType());
            if (!CodeRequestType.isValidCodeRequestType(supportedCodeType, journeyType)) {
                LOG.warn(
                        "Invalid MFA Type '{}' for journey '{}'",
                        NotificationType.MFA_SMS.getMfaMethodType().getValue(),
                        journeyType.getValue());
                return generateApiGatewayProxyErrorResponse(400, INVALID_NOTIFICATION_TYPE);
            }

            if (!userContext.getAuthSession().validateSession(email)) {
                LOG.warn("Email does not match Email in Request");
                auditService.submitAuditEvent(AUTH_MFA_MISMATCHED_EMAIL, auditContext);

                return generateApiGatewayProxyErrorResponse(400, SESSION_ID_MISSING);
            }

            var retrieveMfaMethods = mfaMethodsService.getMfaMethods(email);
            List<MFAMethod> retrievedMfaMethods;
            if (retrieveMfaMethods.isFailure()) {
                var failure = retrieveMfaMethods.getFailure();
                if (failure == USER_DOES_NOT_HAVE_ACCOUNT) {
                    LOG.error(
                            "Error message: Email from session does not have a user profile required, cannot determine if mfa methods are migrated");
                    return generateApiGatewayProxyErrorResponse(400, EMAIL_HAS_NO_USER_PROFILE);
                } else if (failure
                        == UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP) {
                    return generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.AUTH_APP_MFA_ID_ERROR);
                } else {
                    String message =
                            String.format(
                                    "Unexpected error occurred while retrieving mfa methods: %s",
                                    failure);
                    LOG.error(message);
                    return generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR);
                }
            } else {
                retrievedMfaMethods = retrieveMfaMethods.getSuccess();
            }

            var maybeRequestedSmsMfaMethod =
                    getMfaMethodOrDefaultMfaMethod(
                            retrievedMfaMethods, request.getMfaMethodId(), MFAMethodType.SMS);

            if (maybeRequestedSmsMfaMethod.isEmpty()) {
                auditService.submitAuditEvent(AUTH_MFA_MISSING_PHONE_NUMBER, auditContext);
                return generateApiGatewayProxyErrorResponse(400, PHONE_NUMBER_NOT_REGISTERED);
            }

            var requestSmsMfaMethod = maybeRequestedSmsMfaMethod.get();
            var phoneNumber = requestSmsMfaMethod.getDestination();

            var permissionContext =
                    PermissionContext.builder()
                            .withEmailAddress(email)
                            .withE164FormattedPhoneNumber(phoneNumber)
                            .withAuthSessionItem(userContext.getAuthSession())
                            .build();

            var permissionCheckBeforeActionRecorded =
                    ensurePermitted(journeyType, permissionContext, auditContext, false);
            if (permissionCheckBeforeActionRecorded.isPresent()) {
                return permissionCheckBeforeActionRecorded.get();
            }

            auditContext = auditContext.withPhoneNumber(phoneNumber);

            userActionsManager.sentSmsOtpNotification(journeyType, permissionContext);

            var permissionCheckAfterActionRecorded =
                    ensurePermitted(journeyType, permissionContext, auditContext, true);
            if (permissionCheckAfterActionRecorded.isPresent()) {
                return permissionCheckAfterActionRecorded.get();
            }

            var notificationType = (request.isResendCodeRequest()) ? VERIFY_PHONE_NUMBER : MFA_SMS;

            String codeIdentifier = email.concat(PhoneNumberHelper.formatPhoneNumber(phoneNumber));
            String code =
                    codeStorageService
                            .getOtpCode(codeIdentifier, notificationType)
                            .orElseGet(
                                    () -> generateAndSaveNewCode(codeIdentifier, notificationType));

            auditContext =
                    auditContext.withMetadataItem(
                            pair(
                                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                    requestSmsMfaMethod.getPriority().toLowerCase()));

            AuditableEvent auditableEvent;
            if (testUserHelper.isTestJourney(userContext)) {
                LOG.info(
                        "MfaHandler not sending message with NotificationType {}",
                        notificationType);
                auditableEvent = FrontendAuditableEvent.AUTH_MFA_CODE_SENT_FOR_TEST_CLIENT;
            } else {
                LOG.info("Placing message on queue with NotificationType {}", notificationType);
                var notifyRequest =
                        new NotifyRequest(
                                phoneNumber,
                                notificationType,
                                code,
                                userContext.getUserLanguage(),
                                userContext.getAuthSession().getSessionId(),
                                userContext.getClientSessionId());
                sqsClient.send(objectMapper.writeValueAsString(notifyRequest));
                LOG.info(
                        "{} SMS placed on queue with reference: {}",
                        notifyRequest.getNotificationType(),
                        notifyRequest.getUniqueNotificationReference());
                auditableEvent = FrontendAuditableEvent.AUTH_MFA_CODE_SENT;
            }

            auditService.submitAuditEvent(auditableEvent, auditContext);
            LOG.info("Successfully processed request");

            return generateEmptySuccessApiGatewayResponse();
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, REQUEST_MISSING_PARAMS);
        }
    }

    private String generateAndSaveNewCode(String identifier, NotificationType notificationType) {
        LOG.info("No existing OTP found; generating new code");
        String newCode = codeGeneratorService.sixDigitCode();
        codeStorageService.saveOtpCode(
                identifier,
                newCode,
                configurationService.getDefaultOtpCodeExpiry(),
                notificationType);
        return newCode;
    }

    private Optional<APIGatewayProxyResponseEvent> ensurePermitted(
            JourneyType journeyType,
            PermissionContext permissionContext,
            AuditContext auditContext,
            boolean afterActionRecorded) {
        var canSendSmsResult =
                permissionDecisionManager.canSendSmsOtpNotification(journeyType, permissionContext);
        if (canSendSmsResult.isFailure()) {
            return Optional.of(
                    DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(
                            canSendSmsResult.getFailure()));
        }
        if (canSendSmsResult.getSuccess() instanceof Decision.IndefinitelyLockedOut) {
            return Optional.of(
                    generateApiGatewayProxyErrorResponse(
                            400, INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS));
        }
        if (canSendSmsResult.getSuccess() instanceof Decision.TemporarilyLockedOut) {
            auditService.submitAuditEvent(AUTH_MFA_INVALID_CODE_REQUEST, auditContext);
            var errorResponse =
                    afterActionRecorded ? TOO_MANY_MFA_OTPS_SENT : BLOCKED_FOR_SENDING_MFA_OTPS;
            return Optional.of(generateApiGatewayProxyErrorResponse(400, errorResponse));
        }

        var canVerifyResult =
                permissionDecisionManager.canVerifyMfaOtp(journeyType, permissionContext);
        if (canVerifyResult.isFailure()) {
            return Optional.of(
                    DecisionErrorHttpMapper.toApiGatewayProxyErrorResponse(
                            canVerifyResult.getFailure()));
        }
        if (canVerifyResult.getSuccess() instanceof Decision.TemporarilyLockedOut) {
            auditService.submitAuditEvent(AUTH_MFA_INVALID_CODE_REQUEST, auditContext);
            return Optional.of(
                    generateApiGatewayProxyErrorResponse(400, TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        }

        return Optional.empty();
    }
}
