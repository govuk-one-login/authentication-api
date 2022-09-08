package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.SendNotificationRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class SendOtpNotificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SendOtpNotificationHandler.class);

    private final ConfigurationService configurationService;
    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final DynamoService dynamoService;
    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService;

    public SendOtpNotificationHandler(
            ConfigurationService configurationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            DynamoService dynamoService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.dynamoService = dynamoService;
        this.auditService = auditService;
    }

    public SendOtpNotificationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.dynamoService = new DynamoService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public SendOtpNotificationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> sendOtpRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent sendOtpRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOG.info("Request received in SendOtp Lambda");
                            SupportedLanguage userLanguage =
                                    matchSupportedLanguage(
                                            getUserLanguageFromRequestHeaders(
                                                    input.getHeaders(), configurationService));
                            try {
                                SendNotificationRequest sendNotificationRequest =
                                        objectMapper.readValue(
                                                input.getBody(), SendNotificationRequest.class);
                                switch (sendNotificationRequest.getNotificationType()) {
                                    case VERIFY_EMAIL:
                                        LOG.info("NotificationType is VERIFY_EMAIL");
                                        Optional<ErrorResponse> emailErrorResponse =
                                                ValidationHelper.validateEmailAddress(
                                                        sendNotificationRequest.getEmail());
                                        if (emailErrorResponse.isPresent()) {
                                            return generateApiGatewayProxyErrorResponse(
                                                    400, emailErrorResponse.get());
                                        }
                                        if (dynamoService.userExists(
                                                sendNotificationRequest.getEmail())) {
                                            return generateApiGatewayProxyErrorResponse(
                                                    400, ErrorResponse.ERROR_1009);
                                        }
                                        return handleNotificationRequest(
                                                sendNotificationRequest.getEmail(),
                                                sendNotificationRequest,
                                                input,
                                                context,
                                                userLanguage);
                                    case VERIFY_PHONE_NUMBER:
                                        LOG.info("NotificationType is VERIFY_PHONE_NUMBER");
                                        var existingPhoneNumber =
                                                dynamoService
                                                        .getUserProfileByEmailMaybe(
                                                                sendNotificationRequest.getEmail())
                                                        .map(UserProfile::getPhoneNumber)
                                                        .orElse(null);
                                        var phoneNumberValidationError =
                                                ValidationHelper.validatePhoneNumber(
                                                        existingPhoneNumber,
                                                        sendNotificationRequest.getPhoneNumber(),
                                                        configurationService.getEnvironment());
                                        if (phoneNumberValidationError.isPresent()) {
                                            return generateApiGatewayProxyErrorResponse(
                                                    400, phoneNumberValidationError.get());
                                        }
                                        return handleNotificationRequest(
                                                sendNotificationRequest.getPhoneNumber(),
                                                sendNotificationRequest,
                                                input,
                                                context,
                                                userLanguage);
                                }
                                return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
                            } catch (SdkClientException ex) {
                                LOG.error("Error sending message to queue", ex);
                                return generateApiGatewayProxyResponse(
                                        500, "Error sending message to queue");
                            } catch (JsonException e) {
                                return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
                            }
                        });
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination,
            SendNotificationRequest sendNotificationRequest,
            APIGatewayProxyRequestEvent input,
            Context context,
            SupportedLanguage language)
            throws JsonException {

        String code = codeGeneratorService.sixDigitCode();
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        destination, sendNotificationRequest.getNotificationType(), code, language);
        codeStorageService.saveOtpCode(
                sendNotificationRequest.getEmail(),
                code,
                configurationService.getCodeExpiry(),
                sendNotificationRequest.getNotificationType());
        LOG.info(
                "Sending message to SQS queue for notificationType: {}",
                sendNotificationRequest.getNotificationType());
        sqsClient.send(serialiseRequest(notifyRequest));

        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.SEND_OTP,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                sendNotificationRequest.getEmail(),
                IpAddressHelper.extractIpAddress(input),
                sendNotificationRequest.getPhoneNumber(),
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                pair("notification-type", sendNotificationRequest.getNotificationType()));

        LOG.info("Generating successful API response");
        return generateEmptySuccessApiGatewayResponse();
    }

    private String serialiseRequest(Object request) throws JsonException {
        return objectMapper.writeValueAsString(request);
    }
}
