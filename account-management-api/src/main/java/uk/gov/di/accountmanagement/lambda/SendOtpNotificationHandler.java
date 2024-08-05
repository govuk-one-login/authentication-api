package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.SendNotificationRequest;
import uk.gov.di.accountmanagement.exceptions.MissingConfigurationParameterException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.PendingEmailCheckRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class SendOtpNotificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SendOtpNotificationHandler.class);

    private final ConfigurationService configurationService;
    private final AwsSqsClient emailSqsClient;

    private final AwsSqsClient pendingEmailCheckSqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final DynamoService dynamoService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;
    private final ClientService clientService;
    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService;
    private static final String GENERIC_500_ERROR_MESSAGE = "Internal server error";

    public SendOtpNotificationHandler(
            ConfigurationService configurationService,
            AwsSqsClient emailSqsClient,
            AwsSqsClient pendingEmailCheckSqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            DynamoService dynamoService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AuditService auditService,
            ClientService clientService) {
        this.configurationService = configurationService;
        this.emailSqsClient = emailSqsClient;
        this.pendingEmailCheckSqsClient = pendingEmailCheckSqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.dynamoService = dynamoService;
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
        this.clientService = clientService;
    }

    public SendOtpNotificationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
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
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.dynamoService = new DynamoService(configurationService);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
    }

    public SendOtpNotificationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> sendOtpRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent sendOtpRequestHandler(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
        LOG.info("Request received in SendOtp Lambda");

        SendNotificationRequest sendNotificationRequest;
        boolean isTestUserRequest;

        try {
            sendNotificationRequest = parseRequest(input);
            isTestUserRequest = isTestUserJourney(input, sendNotificationRequest);
        } catch (JsonException e) {
            return handleError(e);
        } catch (NullPointerException e) {
            return handleError(
                    "Error reading Client ID from context", e, GENERIC_500_ERROR_MESSAGE);
        } catch (Exception e) {
            return handleError(
                    "Error initializing required variables", e, GENERIC_500_ERROR_MESSAGE);
        }

        if (isTestUserRequest && !configurationService.isTestClientsEnabled()) {
            LOG.warn(
                    "Test user journey attempted, but test clients are not enabled in this environment");
            return generateApiGatewayProxyResponse(500, GENERIC_500_ERROR_MESSAGE);
        }

        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(headers, configurationService));

        try {
            return handleNotificationType(
                    sendNotificationRequest, isTestUserRequest, input, userLanguage);
        } catch (SdkClientException | JsonException e) {
            return handleError(
                    "Error processing notification request", e, "Error sending message to queue");
        }
    }

    private SendNotificationRequest parseRequest(APIGatewayProxyRequestEvent input)
            throws JsonException {
        return objectMapper.readValue(input.getBody(), SendNotificationRequest.class);
    }

    private boolean isTestUserJourney(
            APIGatewayProxyRequestEvent input, SendNotificationRequest request) {
        String clientIdFromApiGateway =
                Objects.requireNonNull(
                                input.getRequestContext().getAuthorizer().get("clientId"),
                                "'clientId' key does not exist in map")
                        .toString();
        return clientService.isTestJourney(clientIdFromApiGateway, request.getEmail());
    }

    private APIGatewayProxyResponseEvent handleError(Exception e) {
        LOG.error("Error parsing sendNotificationRequest", e);
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
    }

    private APIGatewayProxyResponseEvent handleError(
            String message, Exception e, String errorMessage) {
        LOG.error(message, e);
        return generateApiGatewayProxyResponse(500, errorMessage);
    }

    private APIGatewayProxyResponseEvent handleNotificationType(
            SendNotificationRequest sendNotificationRequest,
            boolean isTestUserRequest,
            APIGatewayProxyRequestEvent input,
            SupportedLanguage userLanguage)
            throws JsonException {
        String email = sendNotificationRequest.getEmail();

        return switch (sendNotificationRequest.getNotificationType()) {
            case VERIFY_EMAIL -> handleVerifyEmail(
                    email, sendNotificationRequest, isTestUserRequest, input, userLanguage);
            case VERIFY_PHONE_NUMBER -> handleVerifyPhoneNumber(
                    email, sendNotificationRequest, isTestUserRequest, input, userLanguage);
            default -> generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        };
    }

    private APIGatewayProxyResponseEvent handleVerifyEmail(
            String email,
            SendNotificationRequest sendNotificationRequest,
            boolean isTestUserRequest,
            APIGatewayProxyRequestEvent input,
            SupportedLanguage userLanguage)
            throws JsonException {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        String clientSessionId =
                RequestHeaderHelper.getHeaderValueOrElse(headers, CLIENT_SESSION_ID_HEADER, "");
        String persistentSessionId = PersistentIdHelper.extractPersistentIdFromHeaders(headers);

        Optional<ErrorResponse> emailErrorResponse = ValidationHelper.validateEmailAddress(email);
        if (emailErrorResponse.isPresent()) {
            return generateApiGatewayProxyErrorResponse(400, emailErrorResponse.get());
        }
        if (dynamoService.userExists(email)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
        }
        if (configurationService.isEmailCheckEnabled()) {
            handleEmailCheck(
                    input,
                    email,
                    sessionId,
                    clientSessionId,
                    persistentSessionId,
                    isTestUserRequest);
        }
        return handleNotificationRequest(
                isTestUserRequest, email, sendNotificationRequest, input, userLanguage);
    }

    private APIGatewayProxyResponseEvent handleVerifyPhoneNumber(
            String email,
            SendNotificationRequest sendNotificationRequest,
            boolean isTestUserRequest,
            APIGatewayProxyRequestEvent input,
            SupportedLanguage userLanguage)
            throws JsonException {
        String existingPhoneNumber =
                dynamoService
                        .getUserProfileByEmailMaybe(email)
                        .map(UserProfile::getPhoneNumber)
                        .orElse(null);
        Optional<ErrorResponse> phoneNumberValidationError =
                ValidationHelper.validatePhoneNumber(
                        existingPhoneNumber,
                        sendNotificationRequest.getPhoneNumber(),
                        configurationService.getEnvironment());
        if (phoneNumberValidationError.isPresent()) {
            return generateApiGatewayProxyErrorResponse(400, phoneNumberValidationError.get());
        }
        return handleNotificationRequest(
                isTestUserRequest,
                sendNotificationRequest.getPhoneNumber(),
                sendNotificationRequest,
                input,
                userLanguage);
    }

    private void handleEmailCheck(
            APIGatewayProxyRequestEvent input,
            String email,
            String sessionId,
            String clientSessionId,
            String persistentSessionId,
            boolean isTestUserRequest)
            throws JsonException {
        var emailCheckResult = dynamoEmailCheckResultService.getEmailCheckStore(email);
        if (emailCheckResult.isEmpty()) {
            var userId =
                    input.getRequestContext()
                            .getAuthorizer()
                            .getOrDefault("principalId", AuditService.UNKNOWN)
                            .toString();
            pendingEmailCheckSqsClient.send(
                    objectMapper.writeValueAsString(
                            new PendingEmailCheckRequest(
                                    userId,
                                    UUID.randomUUID(),
                                    email,
                                    sessionId,
                                    clientSessionId,
                                    persistentSessionId,
                                    IpAddressHelper.extractIpAddress(input),
                                    JourneyType.ACCOUNT_MANAGEMENT,
                                    NowHelper.now().toInstant().getEpochSecond(),
                                    isTestUserRequest)));
            LOG.info("Email address check requested");
        } else {
            LOG.info("Skipped request for new email address check. Result already cached");
        }
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            boolean isTestUserRequest,
            String destination,
            SendNotificationRequest sendNotificationRequest,
            APIGatewayProxyRequestEvent input,
            SupportedLanguage language)
            throws JsonException {

        var notificationType = sendNotificationRequest.getNotificationType();
        String code =
                isTestUserRequest
                        ? getOtpCodeForTestClient(notificationType)
                        : codeGeneratorService.sixDigitCode();

        NotifyRequest notifyRequest =
                new NotifyRequest(destination, notificationType, code, language);

        codeStorageService.saveOtpCode(
                sendNotificationRequest.getEmail(),
                code,
                configurationService.getDefaultOtpCodeExpiry(),
                sendNotificationRequest.getNotificationType());

        if (isTestUserRequest) {
            LOG.info(
                    "Test user journey for notificationType: {}. Code saved in code storage service, but no notification will be sent via SQS",
                    sendNotificationRequest.getNotificationType());
        } else {
            LOG.info(
                    "Sending message to SQS queue for notificationType: {}",
                    sendNotificationRequest.getNotificationType());
            emailSqsClient.send(serialiseRequest(notifyRequest));
        }

        var auditContext =
                new AuditContext(
                        input.getRequestContext()
                                .getAuthorizer()
                                .getOrDefault("clientId", AuditService.UNKNOWN)
                                .toString(),
                        ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                        AuditService.UNKNOWN,
                        input.getRequestContext()
                                .getAuthorizer()
                                .getOrDefault("principalId", AuditService.UNKNOWN)
                                .toString(),
                        sendNotificationRequest.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        sendNotificationRequest.getPhoneNumber(),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                        AuditHelper.getTxmaAuditEncoded(input.getHeaders()));

        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.SEND_OTP,
                auditContext,
                pair("notification-type", sendNotificationRequest.getNotificationType()),
                pair("test-user", isTestUserRequest));

        LOG.info("Generating successful API response");
        return generateEmptySuccessApiGatewayResponse();
    }

    private String serialiseRequest(Object request) throws JsonException {
        return objectMapper.writeValueAsString(request);
    }

    private String getOtpCodeForTestClient(NotificationType notificationType) {
        LOG.info("Using TestClient with NotificationType {}", notificationType);
        switch (notificationType) {
            case VERIFY_EMAIL:
                return configurationService.getTestClientVerifyEmailOTP().orElse("");
            case VERIFY_PHONE_NUMBER:
                return configurationService.getTestClientVerifyPhoneNumberOTP().orElse("");
            default:
                LOG.error(
                        "Invalid NotificationType: {} configured for TestClient", notificationType);
                throw new MissingConfigurationParameterException(
                        "Invalid NotificationType for use with TestClient");
        }
    }
}
