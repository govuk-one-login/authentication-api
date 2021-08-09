package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.UpdateClientConfigRequest;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdateClientConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UpdateClientConfigHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public UpdateClientConfigHandler() {
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
            UpdateClientConfigRequest updateClientConfigRequest =
                    objectMapper.readValue(input.getBody(), UpdateClientConfigRequest.class);
            if (!clientService.isValidClient(updateClientConfigRequest.getClientId())) {
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1016);
            }
            ClientRegistry clientRegistry = clientService.updateClient(updateClientConfigRequest);
            ClientRegistrationResponse clientRegistrationResponse =
                    new ClientRegistrationResponse(
                            clientRegistry.getClientName(),
                            clientRegistry.getClientID(),
                            clientRegistry.getRedirectUrls(),
                            clientRegistry.getContacts(),
                            clientRegistry.getPostLogoutRedirectUrls());
            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
