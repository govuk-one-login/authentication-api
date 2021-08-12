package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.UpdateClientConfigRequest;
import uk.gov.di.services.ClientConfigValidationService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdateClientConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ClientConfigValidationService validationService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateClientConfigHandler.class);

    public UpdateClientConfigHandler(
            ClientService clientService, ClientConfigValidationService validationService) {
        this.clientService = clientService;
        this.validationService = validationService;
    }

    public UpdateClientConfigHandler() {
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
            String clientId = input.getPathParameters().get("clientId");
            LOGGER.info("Request received with ClientId {}", clientId);
            UpdateClientConfigRequest updateClientConfigRequest =
                    objectMapper.readValue(input.getBody(), UpdateClientConfigRequest.class);
            if (!clientService.isValidClient(clientId)) {
                LOGGER.error("Client with ClientId {} is not valid", clientId);
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1015);
            }
            Optional<ErrorObject> errorResponse =
                    validationService.validateClientUpdateConfig(updateClientConfigRequest);
            if (errorResponse.isPresent()) {
                return generateApiGatewayProxyResponse(
                        400, errorResponse.get().toJSONObject().toJSONString());
            }
            ClientRegistry clientRegistry =
                    clientService.updateClient(clientId, updateClientConfigRequest);
            ClientRegistrationResponse clientRegistrationResponse =
                    new ClientRegistrationResponse(
                            clientRegistry.getClientName(),
                            clientRegistry.getClientID(),
                            clientRegistry.getRedirectUrls(),
                            clientRegistry.getContacts(),
                            clientRegistry.getScopes(),
                            clientRegistry.getPostLogoutRedirectUrls());
            LOGGER.info("Client with ClientId {} has been updated", clientId);
            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonProcessingException | NullPointerException e) {
            LOGGER.error(
                    "Request with path parameters {} is missing request parameters",
                    input.getPathParameters());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
