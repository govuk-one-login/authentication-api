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
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PHONE_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PHONE_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PHONE_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1011;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class SendNotificationHandler extends BaseFrontendHandler<SendNotificationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SendNotificationHandler.class);
    private static final CloudwatchMetricsService METRICS = new CloudwatchMetricsService();
    private static final List<NotificationType> CONFIRMATION_NOTIFICATION_TYPES =
            List.of(ACCOUNT_CREATED_CONFIRMATION, CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION);

    private final AwsSqsClient emailSqsClient;
    private final AwsSqsClient pendingEmailCheckSqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;
    private final AuditService auditService;

    public SendNotificationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient emailSqsClient,
            AwsSqsClient pendingEmailCheckSqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AuditService auditService) {
        super(
                SendNotificationRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.emailSqsClient = emailSqsClient;
        this.pendingEmailCheckSqsClient = pendingEmailCheckSqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
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
    }

    public SendNotificationHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(SendNotificationRequest.class, configurationService, redis);
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
    }

    public SendNotificationHandler() {
        super(SendNotificationRequest.class, ConfigurationService.getInstance());
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

        attachSessionIdToLogs(userContext.getSession());
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getSession().getInternalCommonSubjectIdentifier(),
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        Optional.ofNullable(request.getPhoneNumber()).orElse(AuditService.UNKNOWN),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        try {
            if (!userContext.getSession().validateSession(request.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            if (CONFIRMATION_NOTIFICATION_TYPES.contains(request.getNotificationType())) {
                LOG.info("Placing message on queue for {}", request.getNotificationType());
                var notifyRequest =
                        new NotifyRequest(
                                request.getEmail(),
                                request.getNotificationType(),
                                userContext.getUserLanguage());
                if (!isTestClientWithAllowedEmail(userContext, configurationService)) {
                    emailSqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                    LOG.info("{} email placed on queue", request.getNotificationType());
                }
                return generateEmptySuccessApiGatewayResponse();
            }
            Optional<ErrorResponse> codeRequestValid =
                    isCodeRequestAttemptValid(
                            request.getEmail(),
                            userContext.getSession(),
                            request.getNotificationType(),
                            request.getJourneyType());
            if (codeRequestValid.isPresent()) {

                auditService.submitAuditEvent(
                        getInvalidCodeAuditEventFromNotificationType(request.getNotificationType()),
                        auditContext);
                return generateApiGatewayProxyErrorResponse(400, codeRequestValid.get());
            }
            switch (request.getNotificationType()) {
                case VERIFY_EMAIL:
                case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                    return handleNotificationRequest(
                            request.getEmail(),
                            request.getNotificationType(),
                            userContext,
                            request.isRequestNewCode(),
                            request,
                            input,
                            auditContext);
                case VERIFY_PHONE_NUMBER:
                    if (request.getPhoneNumber() == null) {
                        return generateApiGatewayProxyResponse(400, ERROR_1011);
                    }
                    var isSmokeTest =
                            userContext.getClient().map(ClientRegistry::isSmokeTest).orElse(false);
                    var errorResponse =
                            ValidationHelper.validatePhoneNumber(
                                    request.getPhoneNumber(),
                                    configurationService.getEnvironment(),
                                    isSmokeTest);
                    if (errorResponse.isPresent()) {
                        return generateApiGatewayProxyResponse(400, errorResponse.get());
                    }
                    return handleNotificationRequest(
                            PhoneNumberHelper.removeWhitespaceFromPhoneNumber(
                                    request.getPhoneNumber()),
                            request.getNotificationType(),
                            userContext,
                            request.isRequestNewCode(),
                            request,
                            input,
                            auditContext);
            }
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue");
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination,
            NotificationType notificationType,
            UserContext userContext,
            Boolean requestNewCode,
            SendNotificationRequest request,
            APIGatewayProxyRequestEvent input,
            AuditContext auditContext)
            throws JsonException, ClientNotFoundException {
        var session = userContext.getSession();

        String code =
                requestNewCode != null && requestNewCode
                        ? generateAndSaveNewCode(session.getEmailAddress(), notificationType)
                        : codeStorageService
                                .getOtpCode(session.getEmailAddress(), notificationType)
                                .orElseGet(
                                        () ->
                                                generateAndSaveNewCode(
                                                        session.getEmailAddress(),
                                                        notificationType));

        LOG.info("Incrementing code request count");
        sessionService.save(
                session.incrementCodeRequestCount(
                        request.getNotificationType(), request.getJourneyType()));
        var testClientWithAllowedEmail =
                isTestClientWithAllowedEmail(userContext, configurationService);

        if (notificationType == NotificationType.VERIFY_EMAIL
                && request.getJourneyType() == JourneyType.REGISTRATION) {

            var emailCheckResult = dynamoEmailCheckResultService.getEmailCheckStore(destination);
            if (emailCheckResult.isEmpty()) {
                String sessionId = userContext.getSession().getSessionId();
                String clientSessionId = userContext.getClientSessionId();
                String persistentSessionId =
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

                pendingEmailCheckSqsClient.send(
                        objectMapper.writeValueAsString(
                                new PendingEmailCheckRequest(
                                        AuditService.UNKNOWN,
                                        UUID.randomUUID(),
                                        destination,
                                        sessionId,
                                        clientSessionId,
                                        persistentSessionId,
                                        IpAddressHelper.extractIpAddress(input),
                                        JourneyType.REGISTRATION,
                                        NowHelper.now().toInstant().getEpochSecond(),
                                        testClientWithAllowedEmail)));
                LOG.info("Email address check requested");
            } else {
                LOG.info("Skipped request for new email address check. Result already cached");
            }
        }

        if (!testClientWithAllowedEmail) {
            if (notificationType == VERIFY_PHONE_NUMBER) {
                METRICS.putEmbeddedValue(
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
                            destination, notificationType, code, userContext.getUserLanguage());
            emailSqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("{} placed on queue", request.getNotificationType());
            LOG.info("Successfully processed request");
        }

        auditService.submitAuditEvent(
                getSuccessfulAuditEventFromNotificationType(
                        notificationType, testClientWithAllowedEmail),
                auditContext);
        return generateEmptySuccessApiGatewayResponse();
    }

    private String generateAndSaveNewCode(String email, NotificationType notificationType) {
        String newCode = codeGeneratorService.sixDigitCode();
        codeStorageService.saveOtpCode(
                email,
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
            Session session,
            NotificationType notificationType,
            JourneyType journeyType) {

        var codeRequestCount = session.getCodeRequestCount(notificationType, journeyType);
        LOG.info("CodeRequestCount is: {}", codeRequestCount);

        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        var newCodeRequestBlockPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
        var codeAttemptsBlockedPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (codeRequestCount == configurationService.getCodeMaxRetries()) {
            LOG.info(
                    "User has requested too many OTP codes. Setting block with prefix: {}",
                    newCodeRequestBlockPrefix);
            codeStorageService.saveBlockedForEmail(
                    email, newCodeRequestBlockPrefix, configurationService.getLockoutDuration());

            LOG.info("Resetting code request count");
            sessionService.save(session.resetCodeRequestCount(notificationType, journeyType));
            return Optional.of(getErrorResponseForCodeRequestLimitReached(notificationType));
        }
        if (codeStorageService.isBlockedForEmail(email, newCodeRequestBlockPrefix)) {
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
        return Optional.empty();
    }

    private ErrorResponse getErrorResponseForCodeRequestLimitReached(
            NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1029;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1030;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return ErrorResponse.ERROR_1046;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private ErrorResponse getErrorResponseForMaxCodeRequests(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1031;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1032;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return ErrorResponse.ERROR_1047;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private ErrorResponse getErrorResponseForMaxCodeAttempts(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1033;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1034;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return ErrorResponse.ERROR_1048;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private AuditableEvent getSuccessfulAuditEventFromNotificationType(
            NotificationType notificationType, boolean isTestClient) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return isTestClient ? EMAIL_CODE_SENT_FOR_TEST_CLIENT : EMAIL_CODE_SENT;
            case VERIFY_PHONE_NUMBER:
                return isTestClient ? PHONE_CODE_SENT_FOR_TEST_CLIENT : PHONE_CODE_SENT;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return isTestClient
                        ? ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT
                        : ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
            default:
                LOG.error(
                        "No successful Audit event configured for NotificationType: {}",
                        notificationType);
                throw new RuntimeException(
                        "No Successful Audit event configured for NotificationType");
        }
    }

    private AuditableEvent getInvalidCodeAuditEventFromNotificationType(
            NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_INVALID_CODE_REQUEST;
            case VERIFY_PHONE_NUMBER:
                return PHONE_INVALID_CODE_REQUEST;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST;
            default:
                LOG.error(
                        "No invalid code request Audit event configured for NotificationType: {}",
                        notificationType);
                throw new RuntimeException(
                        "No Invalid Code Audit event configured for NotificationType");
        }
    }
}
