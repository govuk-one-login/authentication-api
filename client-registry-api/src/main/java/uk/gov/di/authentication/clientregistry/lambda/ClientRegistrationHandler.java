package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.shared.services.AuditService.UNKNOWN;

public class ClientRegistrationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final Json objectMapper = SerializationService.getInstance();
    private final ClientConfigValidationService validationService;
    private final AuditService auditService;
    private static final Logger LOG = LogManager.getLogger(ClientRegistrationHandler.class);

    public ClientRegistrationHandler(
            ClientService clientService,
            ClientConfigValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public ClientRegistrationHandler(ConfigurationService configurationService) {
        this.clientService = new DynamoClientService(configurationService);
        this.validationService = new ClientConfigValidationService();
        this.auditService = new AuditService(configurationService);
    }

    public ClientRegistrationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(() -> clientRegistrationRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent clientRegistrationRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        attachTraceId();
        String ipAddress = IpAddressHelper.extractIpAddress(input);

        var user =
                TxmaAuditUser.user()
                        .withTransactionId(context.getAwsRequestId())
                        .withIpAddress(ipAddress);
        auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_RECEIVED, UNKNOWN, user);

        try {
            LOG.info("Client registration request received");
            var clientRegistrationRequest =
                    objectMapper.readValue(input.getBody(), ClientRegistrationRequest.class);
            var errorResponse =
                    validationService.validateClientRegistrationConfig(clientRegistrationRequest);
            if (errorResponse.isPresent()) {
                LOG.warn(
                        "Invalid Client registration request. Failed validation. Error Code: {}. Error description: {}",
                        errorResponse.get().getCode(),
                        errorResponse.get().getDescription());
                auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR, UNKNOWN, user);

                return generateApiGatewayProxyResponse(
                        400, errorResponse.get().toJSONObject().toJSONString());
            }

            var clientID = clientService.generateClientID().toString();

            attachLogFieldToLogs(CLIENT_ID, clientID);

            clientService.addClient(
                    clientID,
                    clientRegistrationRequest.getClientName(),
                    clientRegistrationRequest.getRedirectUris(),
                    clientRegistrationRequest.getContacts(),
                    clientRegistrationRequest.getPublicKeySource(),
                    clientRegistrationRequest.getPublicKey(),
                    clientRegistrationRequest.getJwksUrl(),
                    clientRegistrationRequest.getScopes(),
                    clientRegistrationRequest.getPostLogoutRedirectUris(),
                    clientRegistrationRequest.getBackChannelLogoutUri(),
                    clientRegistrationRequest.getServiceType(),
                    sanitiseUrl(clientRegistrationRequest.getSectorIdentifierUri()),
                    clientRegistrationRequest.getSubjectType(),
                    clientRegistrationRequest.isJarValidationRequired(),
                    clientRegistrationRequest.getClaims(),
                    clientRegistrationRequest.getClientType(),
                    clientRegistrationRequest.isIdentityVerificationSupported(),
                    null,
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                    clientRegistrationRequest.getIdTokenSigningAlgorithm(),
                    clientRegistrationRequest.getClientLoCs(),
                    clientRegistrationRequest.getChannel(),
                    clientRegistrationRequest.isMaxAgeEnabled(),
                    clientRegistrationRequest.isPkceEnforced(),
                    clientRegistrationRequest.getLandingPageUrl());

            var clientRegistrationResponse =
                    new ClientRegistrationResponse(
                            clientRegistrationRequest.getClientName(),
                            clientID,
                            clientRegistrationRequest.getRedirectUris(),
                            clientRegistrationRequest.getContacts(),
                            clientRegistrationRequest.getPublicKeySource(),
                            clientRegistrationRequest.getPublicKey(),
                            clientRegistrationRequest.getJwksUrl(),
                            clientRegistrationRequest.getScopes(),
                            clientRegistrationRequest.getPostLogoutRedirectUris(),
                            clientRegistrationRequest.getBackChannelLogoutUri(),
                            clientRegistrationRequest.getServiceType(),
                            clientRegistrationRequest.getSubjectType(),
                            clientRegistrationRequest.isJarValidationRequired(),
                            clientRegistrationRequest.getClaims(),
                            clientRegistrationRequest.getSectorIdentifierUri(),
                            clientRegistrationRequest.getClientType(),
                            clientRegistrationRequest.getIdTokenSigningAlgorithm(),
                            clientRegistrationRequest.getChannel(),
                            clientRegistrationRequest.isMaxAgeEnabled(),
                            clientRegistrationRequest.isPkceEnforced(),
                            clientRegistrationRequest.getLandingPageUrl());
            LOG.info("Generating successful Client registration response");
            return generateApiGatewayProxyResponse(200, clientRegistrationResponse);
        } catch (JsonException e) {
            LOG.warn("Invalid Client registration request. Missing parameters from request");
            auditService.submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR, UNKNOWN, user);

            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }

    private String sanitiseUrl(String url) {
        return new UrlValidator().isValid(url) ? url : null;
    }
}
