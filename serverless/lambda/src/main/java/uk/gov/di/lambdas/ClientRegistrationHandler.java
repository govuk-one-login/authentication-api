package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.Client;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.InMemoryClientService;

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
        this.clientService = new InMemoryClientService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            ClientRegistrationRequest clientRegistrationRequest =
                    objectMapper.readValue(input.getBody(), ClientRegistrationRequest.class);
            ClientRegistry clientRegistry =
                    clientService.addClient(
                            clientRegistrationRequest.getClientName(),
                            clientRegistrationRequest.getRedirectUris(),
                            clientRegistrationRequest.getContacts());

            Client client =
                    new Client(
                            clientRegistry.getClientName(),
                            clientRegistry.getClientID(),
                            clientRegistry.getRedirectUrls(),
                            clientRegistry.getContacts());

            return generateApiGatewayProxyResponse(200, client);
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
