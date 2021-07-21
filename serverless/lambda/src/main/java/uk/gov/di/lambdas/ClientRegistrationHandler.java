package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ClientRegistrationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ClientRegistrationHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public ClientRegistrationHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            ClientRegistrationRequest clientRegistrationRequest =
                    objectMapper.readValue(input.getBody(), ClientRegistrationRequest.class);
            String clientID = clientService.generateClientID().toString();
            clientService.addClient(
                    clientID,
                    clientRegistrationRequest.getClientName(),
                    clientRegistrationRequest.getRedirectUris(),
                    clientRegistrationRequest.getContacts(),
                    clientRegistrationRequest.getScopes(),
                    clientRegistrationRequest.getPublicKey(),
                    clientRegistrationRequest.getPostLogoutRedirectUris());

            ClientRegistrationResponse clientRegistrationResponse =
                    new ClientRegistrationResponse(
                            clientRegistrationRequest.getClientName(),
                            clientID,
                            clientRegistrationRequest.getRedirectUris(),
                            clientRegistrationRequest.getContacts(),
                            clientRegistrationRequest.getPostLogoutRedirectUris());

            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
