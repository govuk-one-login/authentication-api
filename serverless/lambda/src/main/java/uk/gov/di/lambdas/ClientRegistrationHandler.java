package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.Client;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.InMemoryClientService;

public class ClientRegistrationHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private ClientService clientService;
    private ObjectMapper objectMapper = new ObjectMapper();

    public ClientRegistrationHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public ClientRegistrationHandler() {
        this.clientService = new InMemoryClientService(new AuthorizationCodeService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();

        try {
            ClientRegistrationRequest clientRegistrationRequest = objectMapper.readValue(input.getBody(), ClientRegistrationRequest.class);
            Client client = clientService.addClient(
                    clientRegistrationRequest.getClientName(),
                    clientRegistrationRequest.getRedirectUris(),
                    clientRegistrationRequest.getContacts());
            String clientString = objectMapper.writeValueAsString(client);
            response.setBody(clientString);
            response.setStatusCode(200);
            return response;
        } catch (JsonProcessingException e) {
            response.setStatusCode(400);
            response.setBody("Request is missing parameters");
            return response;
        }
    }
}
