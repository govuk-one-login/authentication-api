package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.PendingEmailCheckRequest;
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PHONE_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PHONE_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PHONE_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.BLOCKED_FOR_PHONE_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.PHONE_NUMBER_MISSING;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.REQUEST_MISSING_PARAMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.FraudCheckMetricsHelper.incrementUserSubmittedCredentialIfNotificationSetupJourney;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class SendNotificationHandler extends BaseFrontendHandler<SendNotificationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SendNotificationHandler.class);
    private static final List<NotificationType> CONFIRMATION_NOTIFICATION_TYPES =
            List.of(ACCOUNT_CREATED_CONFIRMATION, CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION);
    public static final String AUDIT_EVENT_MFA_METHOD_FIELD = "mfa-method";
    public static final String AUDIT_EVENT_DEFAULT_MFA_VALUE =
            PriorityIdentifier.DEFAULT.toString().toLowerCase();

    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AwsSqsClient emailSqsClient;
    private final AwsSqsClient pendingEmailCheckSqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;
    private final AuditService auditService;
    private final InternationalSmsSendLimitService internationalSmsSendLimitService;
    private final TestUserHelper testUserHelper;

    public SendNotificationHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AwsSqsClient emailSqsClient,
            AwsSqsClient pendingEmailCheckSqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AuditService auditService,
            AuthSessionService authSessionService,
            CloudwatchMetricsService cloudwatchMetricsService,
            InternationalSmsSendLimitService internationalSmsSendLimitService,
            TestUserHelper testUserHelper) {
        super(
                SendNotificationRequest.class,
                configurationService,
                authenticationService,
                true,
                authSessionService);
        this.emailSqsClient = emailSqsClient;
        this.pendingEmailCheckSqsClient = pendingEmailCheckSqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.internationalSmsSendLimitService = internationalSmsSendLimitService;
        this.testUserHelper = testUserHelper;
    }

    public SendNotificationHandler() {
        this(ConfigurationService.getInstance());
    }

    public SendNotificationHandler(ConfigurationService configurationService) {
        super(SendNotificationRequest.class, configurationService);
        this.emailSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.pendingEmailCheckSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getPendingEmailCheckQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.internationalSmsSendLimitService = new InternationalSmsSendLimitService(configurationService);
        this.testUserHelper = new TestUserHelper(configurationService);
    }

    public SendNotificationHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(SendNotificationRequest.class, configurationService);
        this.emailSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.pendingEmailCheckSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getPendingEmailCheckQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.internationalSmsSendLimitService = new InternationalSmsSendLimitService(configurationService);
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
            SendNotificationRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        Optional.ofNullable(request.getPhoneNumber()).orElse(AuditService.UNKNOWN),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        if (!userContext.getAuthSession().validateSession(request.getEmail())) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.SESSION_ID_MISSING);
        }

        if (CONFIRMATION_NOTIFICATION_TYPES.contains(request.getNotificationType())) {
            LOG.info("Placing message on queue for {}", request.getNotificationType());
            var notifyRequest =
                    new NotifyRequest(
                            request.getEmail(),
                            request.getNotificationType(),
                            userContext.getUserLanguage(),
                            userContext.getAuthSession().getSessionId(),
                            userContext.getClientSessionId());

            try {
                if (!testUserHelper.isTestJourney(userContext)) {
                    emailSqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                    LOG.info(
                            "{} EMAIL placed on queue with reference: {}",
                            notifyRequest.getNotificationType(),
                            notifyRequest.getUniqueNotificationReference());
                }
            } catch (Exception e) {
                return generateEmptySuccessApiGatewayResponse();
            }
            return generateEmptySuccessApiGatewayResponse();
        }

        Optional<ErrorResponse> userHasExceededMaximumAllowedCodeRequests =
                isCodeRequestAttemptValid(
                        request.getEmail(),
                        userContext.getAuthSession(),
                        request.getNotificationType(),
                        request.getJourneyType());

        if (userHasExceededMaximumAllowedCodeRequests.isPresent()) {
            auditService.submitAuditEvent(
                    getInvalidCodeAuditEventFromNotificationType(request.getNotificationType()),
                    auditContext);
            return generateApiGatewayProxyErrorResponse(
                    400, userHasExceededMaximumAllowedCodeRequests.get());
        }

        try {
            incrementCountOfNotificationsSent(request, userContext.getAuthSession());

            Optional<ErrorResponse> thisRequestExceedsMaxAllowed =
                    isCodeRequestAttemptValid(
                            request.getEmail(),
                            userContext.getAuthSession(),
                            request.getNotificationType(),
                            request.getJourneyType());

            if (thisRequestExceedsMaxAllowed.isPresent()) {
                auditService.submitAuditEvent(
                        getInvalidCodeAuditEventFromNotificationType(request.getNotificationType()),
                        auditContext);
                return generateApiGatewayProxyErrorResponse(
                        400, thisRequestExceedsMaxAllowed.get());
            }

            switch (request.getNotificationType()) {
                case VERIFY_EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                    return handleNotificationRequest(
                            request.getEmail(),
                            request.getNotificationType(),
                            userContext,
                            request.isRequestNewCode(),
                            request,
                            input,
                            auditContext);
                case VERIFY_PHONE_NUMBER:
                    return handlePhoneNumberVerification(input, request, userContext, auditContext);
                default:
                    return generateApiGatewayProxyErrorResponse(400, INVALID_NOTIFICATION_TYPE);
            }
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue");
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, REQUEST_MISSING_PARAMS);
        }
    }

    private APIGatewayProxyResponseEvent handlePhoneNumberVerification(
            APIGatewayProxyRequestEvent input,
            SendNotificationRequest request,
            UserContext userContext,
            AuditContext auditContext)
            throws JsonException {
        if (request.getPhoneNumber() == null) {
            return generateApiGatewayProxyResponse(400, PHONE_NUMBER_MISSING);
        }

        boolean isSmokeTest = userContext.getAuthSession().getIsSmokeTest();

        var errorResponse =
                ValidationHelper.validatePhoneNumber(
                        request.getPhoneNumber(),
                        configurationService.getEnvironment(),
                        isSmokeTest,
                        configurationService.isInternalApiNewInternationalSmsEnabled());

        if (errorResponse.isPresent()) {
            return generateApiGatewayProxyResponse(400, errorResponse.get());
        }

        auditContext =
                auditContext.withMetadataItem(
                        new AuditService.MetadataPair(
                                AUDIT_EVENT_MFA_METHOD_FIELD,
                                AUDIT_EVENT_DEFAULT_MFA_VALUE,
                                false));

        auditContext =
                auditContext.withMetadataItem(
                        new AuditService.MetadataPair(
                                AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                request.getJourneyType(),
                                false));

        return handleNotificationRequest(
                PhoneNumberHelper.removeWhitespaceFromPhoneNumber(request.getPhoneNumber()),
                request.getNotificationType(),
                userContext,
                request.isRequestNewCode(),
                request,
                input,
                auditContext);
    }

    private void incrementCountOfNotificationsSent(
            SendNotificationRequest request, AuthSessionItem authSessionItem) {
        LOG.info("Incrementing code request count");
        authSessionService.updateSession(
                authSessionItem.incrementCodeRequestCount(
                        request.getNotificationType(), request.getJourneyType()));
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination,
            NotificationType notificationType,
            UserContext userContext,
            Boolean requestNewCode,
            SendNotificationRequest request,
            APIGatewayProxyRequestEvent input,
            AuditContext auditContext)
            throws JsonException {
        var authSession = userContext.getAuthSession();
        var sessionId = authSession.getSessionId();

        String emailAddress = authSession.getEmailAddress();
        String codeIdentifier =
                notificationType.isForPhoneNumber()
                        ? emailAddress.concat(PhoneNumberHelper.formatPhoneNumber(destination))
                        : emailAddress;
        String code;
        if (requestNewCode != null && requestNewCode) {
            code = generateAndSaveNewCode(codeIdentifier, notificationType);
        } else {
            code =
                    codeStorageService
                            .getOtpCode(codeIdentifier, notificationType)
                            .orElseGet(
                                    () -> generateAndSaveNewCode(codeIdentifier, notificationType));
        }

        incrementUserSubmittedCredentialIfNotificationSetupJourney(
                cloudwatchMetricsService,
                request.getJourneyType(),
                request.getNotificationType().name(),
                configurationService.getEnvironment());

        var testClientWithAllowedEmail = testUserHelper.isTestJourney(userContext);

        if (notificationType == NotificationType.VERIFY_EMAIL
                && request.getJourneyType() == JourneyType.REGISTRATION) {

            var emailCheckResult = dynamoEmailCheckResultService.getEmailCheckStore(destination);
            if (emailCheckResult.isEmpty()) {
                String clientSessionId = userContext.getClientSessionId();
                String persistentSessionId =
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

                UUID requestReference = UUID.randomUUID();
                long timeOfInitialRequest = NowHelper.now().toInstant().toEpochMilli();
                pendingEmailCheckSqsClient.send(
                        objectMapper.writeValueAsString(
                                new PendingEmailCheckRequest(
                                        AuditService.UNKNOWN,
                                        requestReference,
                                        destination,
                                        sessionId,
                                        clientSessionId,
                                        persistentSessionId,
                                        IpAddressHelper.extractIpAddress(input),
                                        JourneyType.REGISTRATION,
                                        timeOfInitialRequest,
                                        testClientWithAllowedEmail)));
                LOG.info(
                        "Email address check requested for {} at {}",
                        requestReference,
                        timeOfInitialRequest);
            } else {
                LOG.info("Skipped request for new email address check. Result already cached");
            }
        }

        if (!testClientWithAllowedEmail) {
            if (notificationType == VERIFY_PHONE_NUMBER) {
                if (hasReachedInternationalSmsLimit(destination)) {
                    return generateApiGatewayProxyErrorResponse(400, BLOCKED_FOR_PHONE_VERIFICATION_CODES);
                }

                cloudwatchMetricsService.putEmbeddedValue(
                        "SendingSms",
                        1,
                        Map.of(
                                "Environment",
                                configurationService.getEnvironment(),
                                "Country",
                                PhoneNumberHelper.getCountry(destination)));
            }

            var notifyRequest =
                    new NotifyRequest(
                            destination,
                            notificationType,
                            code,
                            userContext.getUserLanguage(),
                            sessionId,
                            userContext.getClientSessionId());
            emailSqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info(
                    "{} placed on queue with reference: {}",
                    notifyRequest.getNotificationType(),
                    notifyRequest.getUniqueNotificationReference());
        }

        auditService.submitAuditEvent(
                getSuccessfulAuditEventFromNotificationType(
                        notificationType, testClientWithAllowedEmail),
                auditContext);

        return generateEmptySuccessApiGatewayResponse();
    }

    private String generateAndSaveNewCode(String identifier, NotificationType notificationType) {
        String newCode = codeGeneratorService.sixDigitCode();
        codeStorageService.saveOtpCode(
                identifier,
                newCode,
                notificationType.equals(VERIFY_PHONE_NUMBER)
                                || notificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                        ? configurationService.getDefaultOtpCodeExpiry()
                        : configurationService.getEmailAccountCreationOtpCodeExpiry(),
                notificationType);
        return newCode;
    }

    private Optional<ErrorResponse> isCodeRequestAttemptValid(
            String email,
            AuthSessionItem authSession,
            NotificationType notificationType,
            JourneyType journeyType) {

        var codeRequestCount = authSession.getCodeRequestCount(notificationType, journeyType);
        LOG.info("CodeRequestCount is: {}", codeRequestCount);

        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        var newCodeRequestBlockPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
        var codeAttemptsBlockedPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
        var deprecatedCodeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(
                        notificationType.getMfaMethodType(), journeyType);

        if (codeRequestCount >= configurationService.getCodeMaxRetries()) {
            LOG.info(
                    "User has requested too many OTP codes. Setting block with prefix: {}",
                    newCodeRequestBlockPrefix);
            codeStorageService.saveBlockedForEmail(
                    email, newCodeRequestBlockPrefix, configurationService.getLockoutDuration());

            LOG.info("Resetting code request count");
            authSessionService.updateSession(
                    authSession.resetCodeRequestCount(notificationType, journeyType));
            return Optional.of(getErrorResponseForCodeRequestLimitReached(notificationType));
        }
        if (codeStorageService.isBlockedForEmail(email, newCodeRequestBlockPrefix)) {
            LOG.info(
                    "User is blocked from requesting any OTP codes. Code request block prefix: {}",
                    newCodeRequestBlockPrefix);
            return Optional.of(getErrorResponseForMaxCodeRequests(notificationType));
        }
        if (deprecatedCodeRequestType != null
                && codeStorageService.isBlockedForEmail(
                        email, CODE_REQUEST_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType)) {
            LOG.info(
                    "User is blocked from requesting any OTP codes. Code request block prefix: {}",
                    newCodeRequestBlockPrefix);
            return Optional.of(getErrorResponseForMaxCodeRequests(notificationType));
        }
        if (codeStorageService.isBlockedForEmail(email, codeAttemptsBlockedPrefix)) {
            LOG.info(
                    "User is blocked from entering any OTP codes. Code attempt block prefix: {}",
                    codeAttemptsBlockedPrefix);
            return Optional.of(getErrorResponseForMaxCodeAttempts(notificationType));
        }
        if (deprecatedCodeRequestType != null
                && codeStorageService.isBlockedForEmail(
                        email, CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType)) {
            LOG.info(
                    "User is blocked from entering any OTP codes. Code attempt block prefix: {}",
                    codeAttemptsBlockedPrefix);
            return Optional.of(getErrorResponseForMaxCodeAttempts(notificationType));
        }
        return Optional.empty();
    }

    private ErrorResponse getErrorResponseForCodeRequestLimitReached(
            NotificationType notificationType) {
        return switch (notificationType) {
            case VERIFY_EMAIL -> ErrorResponse.TOO_MANY_EMAIL_CODES_SENT;
            case VERIFY_PHONE_NUMBER -> ErrorResponse.TOO_MANY_PHONE_VERIFICATION_CODES_SENT;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> ErrorResponse
                    .TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_SENT;
            default -> {
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
            }
        };
    }

    private ErrorResponse getErrorResponseForMaxCodeRequests(NotificationType notificationType) {
        return switch (notificationType) {
            case VERIFY_EMAIL -> ErrorResponse.BLOCKED_FOR_EMAIL_VERIFICATION_CODES;
            case VERIFY_PHONE_NUMBER -> ErrorResponse.BLOCKED_FOR_PHONE_VERIFICATION_CODES;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> ErrorResponse
                    .BLOCKED_FOR_EMAIL_CODES_FOR_MFA_RESET;
            default -> {
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
            }
        };
    }

    private ErrorResponse getErrorResponseForMaxCodeAttempts(NotificationType notificationType) {
        return switch (notificationType) {
            case VERIFY_EMAIL -> ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED;
            case VERIFY_PHONE_NUMBER -> ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> ErrorResponse
                    .TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED;
            default -> {
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
            }
        };
    }

    private AuditableEvent getSuccessfulAuditEventFromNotificationType(
            NotificationType notificationType, boolean isTestClient) {
        return switch (notificationType) {
            case VERIFY_EMAIL -> isTestClient
                    ? AUTH_EMAIL_CODE_SENT_FOR_TEST_CLIENT
                    : AUTH_EMAIL_CODE_SENT;
            case VERIFY_PHONE_NUMBER -> isTestClient
                    ? AUTH_PHONE_CODE_SENT_FOR_TEST_CLIENT
                    : AUTH_PHONE_CODE_SENT;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> isTestClient
                    ? AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT
                    : AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
            default -> {
                LOG.error(
                        "No successful Audit event configured for NotificationType: {}",
                        notificationType);
                throw new RuntimeException(
                        "No Successful Audit event configured for NotificationType");
            }
        };
    }

    private AuditableEvent getInvalidCodeAuditEventFromNotificationType(
            NotificationType notificationType) {
        return switch (notificationType) {
            case VERIFY_EMAIL -> AUTH_EMAIL_INVALID_CODE_REQUEST;
            case VERIFY_PHONE_NUMBER -> AUTH_PHONE_INVALID_CODE_REQUEST;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST;
            default -> {
                LOG.error(
                        "No invalid code request Audit event configured for NotificationType: {}",
                        notificationType);
                throw new RuntimeException(
                        "No Invalid Code Audit event configured for NotificationType");
            }
        };
    }

    private boolean hasReachedInternationalSmsLimit(String destination) {
        return !PhoneNumberHelper.isDomesticPhoneNumber(destination)
                && !internationalSmsSendLimitService.canSendSms(destination);
    }
}
