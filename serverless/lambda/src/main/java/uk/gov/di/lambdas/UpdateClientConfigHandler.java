package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.services.ClientConfigValidationService;
import uk.gov.di.authentication.frontendapi.services.ClientService;
import uk.gov.di.authentication.frontendapi.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.domain.ClientRegistryAuditableEvent;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.UpdateClientConfigRequest;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdateClientConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ClientConfigValidationService validationService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateClientConfigHandler.class);

    public UpdateClientConfigHandler(
            ClientService clientService,
            ClientConfigValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public UpdateClientConfigHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.validationService = new ClientConfigValidationService();
        this.auditService = new AuditService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        auditService.submitAuditEvent(ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED);

        try {
            String clientId = input.getPathParameters().get("clientId");
            LOGGER.info("Request received with ClientId {}", clientId);
            UpdateClientConfigRequest updateClientConfigRequest =
                    objectMapper.readValue(input.getBody(), UpdateClientConfigRequest.class);
            if (!clientService.isValidClient(clientId)) {
                auditService.submitAuditEvent(
                        ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR);
                LOGGER.error("Client with ClientId {} is not valid", clientId);
                return generateApiGatewayProxyResponse(
                        400, OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString());
            }
            Optional<ErrorObject> errorResponse =
                    validationService.validateClientUpdateConfig(updateClientConfigRequest);
            if (errorResponse.isPresent()) {
                auditService.submitAuditEvent(
                        ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR);
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
                            clientRegistry.getPostLogoutRedirectUrls(),
                            clientRegistry.getServiceType());
            LOGGER.info("Client with ClientId {} has been updated", clientId);
            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonProcessingException | NullPointerException e) {
            auditService.submitAuditEvent(ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR);
            LOGGER.error(
                    "Request with path parameters {} is missing request parameters",
                    input.getPathParameters());
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }
}
