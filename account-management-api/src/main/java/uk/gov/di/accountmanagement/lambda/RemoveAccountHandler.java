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
import uk.gov.di.accountmanagement.entity.RemoveAccountRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.validatePrincipal;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class RemoveAccountHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoveAccountHandler.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public RemoveAccountHandler(
            AuthenticationService authenticationService, AwsSqsClient sqsClient) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
    }

    public RemoveAccountHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                LOGGER.info("RemoveAccountHandler received request");
                                RemoveAccountRequest removeAccountRequest =
                                        objectMapper.readValue(
                                                input.getBody(), RemoveAccountRequest.class);

                                String email = removeAccountRequest.getEmail();

                                Subject subjectFromEmail =
                                        authenticationService.getSubjectFromEmail(email);
                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();
                                validatePrincipal(subjectFromEmail, authorizerParams);

                                authenticationService.removeAccount(email);
                                LOGGER.info("User account removed. Adding message to SQS queue");

                                NotifyRequest notifyRequest =
                                        new NotifyRequest(email, NotificationType.DELETE_ACCOUNT);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                                LOGGER.info(
                                        "Remove account message successfully added to queue. Generating successful gateway response");
                                return generateApiGatewayProxyResponse(200, "");
                            } catch (JsonProcessingException e) {
                                LOGGER.error(
                                        "RemoveAccountRequest request is missing or contains invalid parameters.",
                                        e);
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
