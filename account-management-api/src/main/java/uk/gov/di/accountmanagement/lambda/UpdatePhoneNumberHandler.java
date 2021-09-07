package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePhoneNumberRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdatePhoneNumberHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final ValidationService validationService;
    private final CodeStorageService codeStorageService;
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdatePhoneNumberHandler.class);

    public UpdatePhoneNumberHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.validationService = new ValidationService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
    }

    public UpdatePhoneNumberHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            ValidationService validationService,
            CodeStorageService codeStorageService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.validationService = validationService;
        this.codeStorageService = codeStorageService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOGGER.info("UpdatePhoneNumberHandler received request");
        try {
            UpdatePhoneNumberRequest updatePhoneNumberRequest =
                    objectMapper.readValue(input.getBody(), UpdatePhoneNumberRequest.class);
            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            updatePhoneNumberRequest.getEmail(),
                            updatePhoneNumberRequest.getOtp(),
                            NotificationType.VERIFY_PHONE_NUMBER);
            if (!isValidOtpCode) {
                LOGGER.error("Invalid OTP code sent in request");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
            }
            Optional<ErrorResponse> phoneValidationErrors =
                    validationService.validatePhoneNumber(
                            updatePhoneNumberRequest.getPhoneNumber());
            if (phoneValidationErrors.isPresent()) {
                LOGGER.error(
                        "Invalid phone number with error: {}",
                        phoneValidationErrors.get().getMessage());
                return generateApiGatewayProxyErrorResponse(400, phoneValidationErrors.get());
            }
            Subject subjectFromEmail =
                    dynamoService.getSubjectFromEmail(updatePhoneNumberRequest.getEmail());
            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            RequestBodyHelper.validatePrincipal(subjectFromEmail, authorizerParams);
            dynamoService.updatePhoneNumber(
                    updatePhoneNumberRequest.getEmail(),
                    updatePhoneNumberRequest.getPhoneNumber());
            LOGGER.info("Phone Number has successfully been updated. Adding message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            updatePhoneNumberRequest.getEmail(),
                            NotificationType.PHONE_NUMBER_UPDATED);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOGGER.info(
                    "Message successfully added to queue. Generating successful gateway response");
            return generateApiGatewayProxyResponse(200, "");
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error("UpdatePhoneNumber request is missing or contains invalid parameters.", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
