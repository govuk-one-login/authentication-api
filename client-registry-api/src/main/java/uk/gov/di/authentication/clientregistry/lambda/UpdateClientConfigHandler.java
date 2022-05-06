package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdateClientConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ClientConfigValidationService validationService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    private static final Logger LOG = LogManager.getLogger(UpdateClientConfigHandler.class);

    public UpdateClientConfigHandler(
            ClientService clientService,
            ClientConfigValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public UpdateClientConfigHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateClientConfigHandler(ConfigurationService configurationService) {
        this.clientService = new DynamoClientService(configurationService);
        this.validationService = new ClientConfigValidationService();
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall("client-registry-api::" + getClass().getSimpleName(), () -> updateClientRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updateClientRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String ipAddress = IpAddressHelper.extractIpAddress(input);
                            auditService.submitAuditEvent(
                                    UPDATE_CLIENT_REQUEST_RECEIVED,
                                    context.getAwsRequestId(),
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    ipAddress,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN);
                            try {
                                String clientId = input.getPathParameters().get("clientId");

                                attachLogFieldToLogs(CLIENT_ID, clientId);

                                LOG.info("Update client config request received");

                                var updateClientConfigRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdateClientConfigRequest.class);
                                if (!clientService.isValidClient(clientId)) {
                                    auditService.submitAuditEvent(
                                            UPDATE_CLIENT_REQUEST_ERROR,
                                            context.getAwsRequestId(),
                                            AuditService.UNKNOWN,
                                            clientId,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            ipAddress,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN);
                                    LOG.warn("Invalid client id");
                                    return generateApiGatewayProxyResponse(
                                            400,
                                            OAuth2Error.INVALID_CLIENT
                                                    .toJSONObject()
                                                    .toJSONString());
                                }
                                Optional<ErrorObject> errorResponse =
                                        validationService.validateClientUpdateConfig(
                                                updateClientConfigRequest);
                                if (errorResponse.isPresent()) {
                                    LOG.warn(
                                            "Failed validation. ErrorCode: {}. ErrorDescription: {}",
                                            errorResponse.get().getCode(),
                                            errorResponse.get().getDescription());
                                    auditService.submitAuditEvent(
                                            UPDATE_CLIENT_REQUEST_ERROR,
                                            context.getAwsRequestId(),
                                            AuditService.UNKNOWN,
                                            clientId,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            ipAddress,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN);
                                    return generateApiGatewayProxyResponse(
                                            400, errorResponse.get().toJSONObject().toJSONString());
                                }
                                ClientRegistry clientRegistry =
                                        clientService.updateClient(
                                                clientId, updateClientConfigRequest);
                                ClientRegistrationResponse clientRegistrationResponse =
                                        new ClientRegistrationResponse(
                                                clientRegistry.getClientName(),
                                                clientRegistry.getClientID(),
                                                clientRegistry.getRedirectUrls(),
                                                clientRegistry.getContacts(),
                                                clientRegistry.getScopes(),
                                                clientRegistry.getPostLogoutRedirectUrls(),
                                                clientRegistry.getBackChannelLogoutUri(),
                                                clientRegistry.getServiceType(),
                                                clientRegistry.getSubjectType(),
                                                clientRegistry.getClaims(),
                                                clientRegistry.getSectorIdentifierUri(),
                                                clientRegistry.getClientType());
                                LOG.info("Client updated");
                                return generateApiGatewayProxyResponse(
                                        200, clientRegistrationResponse);
                            } catch (JsonProcessingException | NullPointerException e) {
                                auditService.submitAuditEvent(
                                        UPDATE_CLIENT_REQUEST_ERROR,
                                        context.getAwsRequestId(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        ipAddress,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN);
                                LOG.warn(
                                        "Invalid Client registration request. Missing parameters from request");
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
                            }
                        });
    }
}
