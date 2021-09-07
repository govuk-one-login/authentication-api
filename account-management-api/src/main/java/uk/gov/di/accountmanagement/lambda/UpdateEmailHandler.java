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
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
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

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final ValidationService validationService;
    private final CodeStorageService codeStorageService;
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateEmailHandler.class);

    public UpdateEmailHandler() {
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

    public UpdateEmailHandler(
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
        LOGGER.info("UpdateEmailHandler received request");
        LOGGER.info(
                "Authorizer parameters received: {}", input.getRequestContext().getAuthorizer());
        try {
            UpdateEmailRequest updateInfoRequest =
                    objectMapper.readValue(input.getBody(), UpdateEmailRequest.class);
            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            updateInfoRequest.getExistingEmailAddress(),
                            updateInfoRequest.getOtp(),
                            NotificationType.VERIFY_EMAIL);
            if (!isValidOtpCode) {
                LOGGER.error(
                        "Invalid OTP code sent in request");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
            }
            Optional<ErrorResponse> emailValidationErrors =
                    validationService.validateEmailAddressUpdate(
                            updateInfoRequest.getExistingEmailAddress(),
                            updateInfoRequest.getReplacementEmailAddress());
            if (emailValidationErrors.isPresent()) {
                LOGGER.error(
                        "Invalid email address with error: {}",
                        emailValidationErrors.get().getMessage());
                return generateApiGatewayProxyErrorResponse(400, emailValidationErrors.get());
            }
            Subject subjectFromEmail =
                    dynamoService.getSubjectFromEmail(updateInfoRequest.getExistingEmailAddress());
            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            RequestBodyHelper.validatePrincipal(subjectFromEmail, authorizerParams);
            dynamoService.updateEmail(
                    updateInfoRequest.getExistingEmailAddress(),
                    updateInfoRequest.getReplacementEmailAddress());
            LOGGER.info("Email has successfully been updated. Adding message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            updateInfoRequest.getReplacementEmailAddress(),
                            NotificationType.EMAIL_UPDATED);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOGGER.info(
                    "Message successfully added to queue. Generating successful gateway response");
            return generateApiGatewayProxyResponse(200, "");
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error("UpdateInfo request is missing or contains invalid parameters.", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
