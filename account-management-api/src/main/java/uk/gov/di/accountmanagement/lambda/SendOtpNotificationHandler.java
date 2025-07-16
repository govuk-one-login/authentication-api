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
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_AUTH;
import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.NEW_PHONE_NUMBER_ALREADY_IN_USE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.REQUEST_MISSING_PARAMS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.FraudCheckMetricsHelper.incrementUserSubmittedCredentialIfNotificationSetupJourney;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueOrElse;
import static uk.gov.di.authentication.shared.helpers.ValidationHelper.validatePhoneNumber;
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
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final MFAMethodsService mfaMethodsService;

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
            ClientService clientService,
            CloudwatchMetricsService cloudwatchMetricsService,
            MFAMethodsService mfaMethodsService) {
        this.configurationService = configurationService;
        this.emailSqsClient = emailSqsClient;
        this.pendingEmailCheckSqsClient = pendingEmailCheckSqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.dynamoService = dynamoService;
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
        this.clientService = clientService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.mfaMethodsService = mfaMethodsService;
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
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.mfaMethodsService = new MFAMethodsService(configurationService);
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
                () -> sendOtpRequestHandler(input, context));
    }

    private Result<APIGatewayProxyResponseEvent, SendNotificationRequest> checkRequestFormat(
            APIGatewayProxyRequestEvent input) {
        try {
            var sendNotificationRequest =
                    objectMapper.readValue(input.getBody(), SendNotificationRequest.class);
            return Result.success(sendNotificationRequest);
        } catch (JsonException e) {
            LOG.error("Error parsing sendNotificationRequest", e);
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, REQUEST_MISSING_PARAMS));
        }
    }

    private Result<APIGatewayProxyResponseEvent, Boolean> checkForTestUser(
            APIGatewayProxyRequestEvent input, SendNotificationRequest sendNotificationRequest) {
        try {
            String clientIdFromApiGateway =
                    (String)
                            Objects.requireNonNull(
                                    input.getRequestContext().getAuthorizer().get("clientId"),
                                    "'clientId' key does not exist in map");
            boolean isTestUserRequest =
                    clientService.isTestJourney(
                            clientIdFromApiGateway, sendNotificationRequest.getEmail());

            if (isTestUserRequest && !configurationService.isTestClientsEnabled()) {
                LOG.warn(
                        "Test user journey attempted, but test clients are not enabled in this environment");
                return Result.failure(
                        generateApiGatewayProxyResponse(500, GENERIC_500_ERROR_MESSAGE));
            }

            return Result.success(isTestUserRequest);
        } catch (NullPointerException e) {
            LOG.error("Error reading Client ID from context (passed from API Gateway)", e);
            return Result.failure(generateApiGatewayProxyResponse(500, GENERIC_500_ERROR_MESSAGE));
        } catch (Exception e) {
            LOG.error(
                    "Error initialising required variables for Account Management Send OTP Handler",
                    e);
            return Result.failure(generateApiGatewayProxyResponse(500, GENERIC_500_ERROR_MESSAGE));
        }
    }

    public APIGatewayProxyResponseEvent sendOtpRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) throws JsonException {
        LOG.info("Request received in SendOtp Lambda");

        Map<String, String> headers = input.getHeaders();
        String sessionId = getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        String clientSessionId = getHeaderValueOrElse(headers, CLIENT_SESSION_ID_HEADER, "");
        String persistentSessionId = extractPersistentIdFromHeaders(headers);

        attachSessionIdToLogs(sessionId);

        var checkRequestFormatResult = checkRequestFormat(input);

        if (checkRequestFormatResult.isFailure()) {
            return checkRequestFormatResult.getFailure();
        }

        var sendNotificationRequest = checkRequestFormatResult.getSuccess();

        var checkForTestUserResult = checkForTestUser(input, sendNotificationRequest);

        if (checkForTestUserResult.isFailure()) {
            return checkForTestUserResult.getFailure();
        }

        boolean isTestUserRequest = checkForTestUserResult.getSuccess();

        incrementUserSubmittedCredentialIfNotificationSetupJourney(
                cloudwatchMetricsService,
                JourneyType.ACCOUNT_MANAGEMENT,
                sendNotificationRequest.getNotificationType().name(),
                configurationService.getEnvironment());

        if (sendNotificationRequest.getNotificationType() == null) {
            return generateApiGatewayProxyErrorResponse(400, INVALID_NOTIFICATION_TYPE);
        }

        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(headers, configurationService));

        String email = sendNotificationRequest.getEmail();

        Optional<ErrorResponse> emailErrorResponse = ValidationHelper.validateEmailAddress(email);

        if (emailErrorResponse.isPresent()) {
            return generateApiGatewayProxyErrorResponse(400, emailErrorResponse.get());
        }

        switch (sendNotificationRequest.getNotificationType()) {
            case VERIFY_EMAIL -> {
                LOG.info("NotificationType is VERIFY_EMAIL");

                if (dynamoService.userExists(email)) {
                    return generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ACCT_WITH_EMAIL_EXISTS);
                }

                checkEmail(
                        input,
                        email,
                        sessionId,
                        clientSessionId,
                        persistentSessionId,
                        isTestUserRequest);

                return handleNotificationRequest(
                        isTestUserRequest,
                        email,
                        sendNotificationRequest,
                        input,
                        context,
                        userLanguage);
            }
            case VERIFY_PHONE_NUMBER -> {
                LOG.info("NotificationType is VERIFY_PHONE_NUMBER");

                var response =
                        validatePhoneNumber(
                                sendNotificationRequest.getPhoneNumber(),
                                configurationService.getEnvironment(),
                                false);

                if (response.isPresent()) {
                    return generateApiGatewayProxyErrorResponse(400, response.get());
                }

                String newPhoneNumber;

                newPhoneNumber =
                        PhoneNumberHelper.formatPhoneNumber(
                                sendNotificationRequest.getPhoneNumber());

                var inUseResult =
                        mfaMethodsService.isPhoneAlreadyInUseAsAVerifiedMfa(email, newPhoneNumber);

                if (inUseResult.isFailure()) {
                    return generateApiGatewayProxyErrorResponse(400, inUseResult.getFailure());
                }

                if (Boolean.TRUE.equals(inUseResult.getSuccess())) {
                    return generateApiGatewayProxyErrorResponse(
                            400, NEW_PHONE_NUMBER_ALREADY_IN_USE);
                }

                return handleNotificationRequest(
                        isTestUserRequest,
                        sendNotificationRequest.getPhoneNumber(),
                        sendNotificationRequest,
                        input,
                        context,
                        userLanguage);
            }
            default -> {
                return generateApiGatewayProxyErrorResponse(400, INVALID_NOTIFICATION_TYPE);
            }
        }
    }

    private void checkEmail(
            APIGatewayProxyRequestEvent input,
            String email,
            String sessionId,
            String clientSessionId,
            String persistentSessionId,
            boolean isTestUserRequest)
            throws JsonException {
        if (configurationService.isEmailCheckEnabled()) {
            var emailCheckResult = dynamoEmailCheckResultService.getEmailCheckStore(email);
            if (emailCheckResult.isEmpty()) {
                var userId =
                        input.getRequestContext()
                                .getAuthorizer()
                                .getOrDefault("principalId", AuditService.UNKNOWN)
                                .toString();
                UUID requestReference = UUID.randomUUID();
                long timeOfInitialRequest = NowHelper.now().toInstant().toEpochMilli();
                pendingEmailCheckSqsClient.send(
                        objectMapper.writeValueAsString(
                                new PendingEmailCheckRequest(
                                        userId,
                                        requestReference,
                                        email,
                                        sessionId,
                                        clientSessionId,
                                        persistentSessionId,
                                        IpAddressHelper.extractIpAddress(input),
                                        JourneyType.ACCOUNT_MANAGEMENT,
                                        timeOfInitialRequest,
                                        isTestUserRequest)));
                LOG.info(
                        "Email address check requested for {} at {}",
                        requestReference,
                        timeOfInitialRequest);
            } else {
                LOG.info("Skipped request for new email address check. Result already cached");
            }
        }
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            boolean isTestUserRequest,
            String destination,
            SendNotificationRequest sendNotificationRequest,
            APIGatewayProxyRequestEvent input,
            Context context,
            SupportedLanguage language)
            throws JsonException {

        var notificationType = sendNotificationRequest.getNotificationType();
        String code =
                isTestUserRequest
                        ? getOtpCodeForTestClient(notificationType)
                        : codeGeneratorService.sixDigitCode();

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        destination,
                        notificationType,
                        code,
                        language,
                        isTestUserRequest,
                        sendNotificationRequest.getEmail());

        codeStorageService.saveOtpCode(
                sendNotificationRequest.getEmail(),
                code,
                configurationService.getDefaultOtpCodeExpiry(),
                sendNotificationRequest.getNotificationType());

        LOG.info(
                "Sending message to SQS queue for notificationType: {} for client type: {}",
                sendNotificationRequest.getNotificationType(),
                isTestUserRequest);

        try {
            emailSqsClient.send(serialiseRequest(notifyRequest));
        } catch (SdkClientException e) {
            LOG.error("Error sending message to queue");
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
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
                        extractPersistentIdFromHeaders(input.getHeaders()),
                        AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                        new ArrayList<>());

        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.AUTH_SEND_OTP,
                auditContext,
                AUDIT_EVENT_COMPONENT_ID_AUTH,
                pair("notification-type", sendNotificationRequest.getNotificationType()),
                pair("test-user", isTestUserRequest));

        if (notificationType == NotificationType.VERIFY_PHONE_NUMBER) {
            auditService.submitAuditEvent(
                    AccountManagementAuditableEvent.AUTH_PHONE_CODE_SENT,
                    auditContext,
                    AUDIT_EVENT_COMPONENT_ID_HOME,
                    pair(
                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                            JourneyType.ACCOUNT_MANAGEMENT.name()),
                    pair(
                            AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                            PriorityIdentifier.DEFAULT.name().toLowerCase()));
        }

        LOG.info("Generating successful API response");
        return generateEmptySuccessApiGatewayResponse();
    }

    private String serialiseRequest(Object request) throws JsonException {
        return objectMapper.writeValueAsString(request);
    }

    private String getOtpCodeForTestClient(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return configurationService.getTestClientVerifyEmailOTP().orElse("");
            case VERIFY_PHONE_NUMBER:
                return configurationService.getTestClientVerifyPhoneNumberOTP().orElse("");
            default:
                // Unreachable code.
                LOG.error(
                        "Invalid NotificationType: {} configured for TestClient", notificationType);
                throw new MissingConfigurationParameterException(
                        "Invalid NotificationType for use with TestClient");
        }
    }
}
