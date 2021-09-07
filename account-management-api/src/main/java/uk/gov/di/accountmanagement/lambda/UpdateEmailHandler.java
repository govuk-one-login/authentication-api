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
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateEmailHandler.class);

    public UpdateEmailHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    public UpdateEmailHandler(DynamoService dynamoService, AwsSqsClient sqsClient) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
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
            Subject subjectFromEmail =
                    dynamoService.getSubjectFromEmail(updateInfoRequest.getExistingEmailAddress());
            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

            if (!authorizerParams.containsKey("principalId")) {
                LOGGER.error("principalId is missing");
                throw new RuntimeException("principalId is missing");
            } else if (!subjectFromEmail.getValue().equals(authorizerParams.get("principalId"))) {
                LOGGER.error(
                        "Subject ID: {} does not match principalId: {}",
                        subjectFromEmail,
                        authorizerParams.get("principalId"));
                throw new RuntimeException("Subject ID does not match principalId");
            }
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
