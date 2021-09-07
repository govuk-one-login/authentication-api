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
import uk.gov.di.authentication.shared.helpers.StateMachine;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.validatePrincipal;

public class RemoveAccountHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoveAccountHandler.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public RemoveAccountHandler(AuthenticationService authenticationService, AwsSqsClient sqsClient) {
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
        try {
            RemoveAccountRequest removeAccountRequest =
                    objectMapper.readValue(input.getBody(), RemoveAccountRequest.class);

            String email = removeAccountRequest.getEmail();
            Subject subjectFromEmail =
                    authenticationService.getSubjectFromEmail(email);
            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

            validatePrincipal(subjectFromEmail, authorizerParams);

            if (!authenticationService.userExists(email)) {
                LOGGER.info("User account does not exist");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
            }

            authenticationService.removeAccount(email);
            LOGGER.info("User account removed");

            NotifyRequest notifyRequest = new NotifyRequest(email, NotificationType.DELETE_ACCOUNT);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOGGER.info("Remove account message successfully added to queue.");

            return generateApiGatewayProxyResponse(200, "");
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
