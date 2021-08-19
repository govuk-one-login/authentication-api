package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.services.ClientConfigValidationService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ClientRegistrationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ClientConfigValidationService validationService;

    public ClientRegistrationHandler(
            ClientService clientService, ClientConfigValidationService validationService) {
        this.clientService = clientService;
        this.validationService = validationService;
    }

    public ClientRegistrationHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.validationService = new ClientConfigValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            ClientRegistrationRequest clientRegistrationRequest =
                    objectMapper.readValue(input.getBody(), ClientRegistrationRequest.class);
            Optional<ErrorObject> errorResponse =
                    validationService.validateClientRegistrationConfig(clientRegistrationRequest);
            if (errorResponse.isPresent()) {
                return generateApiGatewayProxyResponse(
                        400, errorResponse.get().toJSONObject().toJSONString());
            }
            String clientID = clientService.generateClientID().toString();
            clientService.addClient(
                    clientID,
                    clientRegistrationRequest.getClientName(),
                    clientRegistrationRequest.getRedirectUris(),
                    clientRegistrationRequest.getContacts(),
                    clientRegistrationRequest.getScopes(),
                    clientRegistrationRequest.getPublicKey(),
                    clientRegistrationRequest.getPostLogoutRedirectUris(),
                    clientRegistrationRequest.getServiceType());

            ClientRegistrationResponse clientRegistrationResponse =
                    new ClientRegistrationResponse(
                            clientRegistrationRequest.getClientName(),
                            clientID,
                            clientRegistrationRequest.getRedirectUris(),
                            clientRegistrationRequest.getContacts(),
                            clientRegistrationRequest.getScopes(),
                            clientRegistrationRequest.getPostLogoutRedirectUris(),
                            clientRegistrationRequest.getServiceType());

            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }
}
