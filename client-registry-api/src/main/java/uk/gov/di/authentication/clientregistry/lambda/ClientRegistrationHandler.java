package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.commons.validator.routines.UrlValidator;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class ClientRegistrationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ClientConfigValidationService validationService;
    private final AuditService auditService;

    public ClientRegistrationHandler(
            ClientService clientService,
            ClientConfigValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public ClientRegistrationHandler() {
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
        return isWarming(input)
                .orElseGet(
                        () -> {
                            auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_RECEIVED);

                            try {
                                ClientRegistrationRequest clientRegistrationRequest =
                                        objectMapper.readValue(
                                                input.getBody(), ClientRegistrationRequest.class);
                                Optional<ErrorObject> errorResponse =
                                        validationService.validateClientRegistrationConfig(
                                                clientRegistrationRequest);
                                if (errorResponse.isPresent()) {
                                    auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR);

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
                                        clientRegistrationRequest.getServiceType(),
                                        sanitiseUrl(
                                                clientRegistrationRequest.getSectorIdentifierUri()),
                                        clientRegistrationRequest.getSubjectType());

                                ClientRegistrationResponse clientRegistrationResponse =
                                        new ClientRegistrationResponse(
                                                clientRegistrationRequest.getClientName(),
                                                clientID,
                                                clientRegistrationRequest.getRedirectUris(),
                                                clientRegistrationRequest.getContacts(),
                                                clientRegistrationRequest.getScopes(),
                                                clientRegistrationRequest
                                                        .getPostLogoutRedirectUris(),
                                                clientRegistrationRequest.getServiceType());

                                return generateApiGatewayProxyResponse(
                                        200, clientRegistrationResponse);
                            } catch (JsonProcessingException e) {
                                auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR);

                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
                            }
                        });
    }

    private String sanitiseUrl(String url) {
        return new UrlValidator().isValid(url) ? url : null;
    }
}
