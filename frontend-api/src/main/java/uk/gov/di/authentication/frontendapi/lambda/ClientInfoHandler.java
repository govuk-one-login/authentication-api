package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ClientInfoResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class ClientInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientInfoHandler.class);
    private final ConfigurationService configurationService;
    private final ClientSessionService clientSessionService;
    private final ClientService clientService;
    private final SessionService sessionService;
    private final AuditService auditService;

    public ClientInfoHandler(
            ConfigurationService configurationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            SessionService sessionService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.clientSessionService = clientSessionService;
        this.clientService = clientService;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    public ClientInfoHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.clientSessionService = new ClientSessionService(configurationService);
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.sessionService = new SessionService(configurationService);
        this.auditService = new AuditService();
    }

    public ClientInfoHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("ClientInfo request received");
                            Optional<Session> session =
                                    sessionService.getSessionFromRequestHeaders(input.getHeaders());
                            if (session.isEmpty()) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            }

                            Optional<ClientSession> clientSession =
                                    clientSessionService.getClientSessionFromRequestHeaders(
                                            input.getHeaders());

                            if (clientSession.isEmpty()) {
                                LOGGER.info(
                                        "ClientSession not found for session: {}",
                                        session.get().getSessionId());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1018);
                            }

                            try {
                                Map<String, List<String>> authRequest =
                                        clientSession.get().getAuthRequestParams();

                                AuthenticationRequest authenticationRequest =
                                        AuthenticationRequest.parse(authRequest);
                                String clientID = authenticationRequest.getClientID().getValue();
                                String state = authenticationRequest.getState().getValue();
                                String redirectUri =
                                        authenticationRequest.getRedirectionURI().toString();

                                List<String> scopes =
                                        authenticationRequest.getScope().toStringList();

                                Optional<ClientRegistry> optionalClientRegistry =
                                        clientService.getClient(clientID);

                                if (optionalClientRegistry.isEmpty()) {
                                    LOGGER.error(
                                            "ClientId: {} not found in ClientRegistry for session: {}",
                                            clientID,
                                            session.get().getSessionId());
                                    return generateApiGatewayProxyErrorResponse(
                                            403, ErrorResponse.ERROR_1015);
                                }

                                ClientRegistry clientRegistry = optionalClientRegistry.get();
                                ClientInfoResponse clientInfoResponse =
                                        new ClientInfoResponse(
                                                clientRegistry.getClientID(),
                                                clientRegistry.getClientName(),
                                                scopes,
                                                redirectUri,
                                                clientRegistry.getServiceType(),
                                                state);

                                LOGGER.info(
                                        "Found Client Info for ClientID: {} ClientName {} Scopes {} Redirect Uri {} Service Type {} State {} for session: {}",
                                        clientRegistry.getClientID(),
                                        clientRegistry.getClientName(),
                                        scopes,
                                        redirectUri,
                                        clientRegistry.getServiceType(),
                                        state,
                                        session.get().getSessionId());

                                auditService.submitAuditEvent(
                                        FrontendAuditableEvent.CLIENT_INFO_FOUND,
                                        context.getAwsRequestId(),
                                        session.get().getSessionId(),
                                        clientRegistry.getClientID(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        IpAddressHelper.extractIpAddress(input),
                                        AuditService.UNKNOWN);

                                return generateApiGatewayProxyResponse(200, clientInfoResponse);

                            } catch (ParseException | JsonProcessingException e) {
                                LOGGER.error(
                                        "Error when calling ClientInfo for session: {}",
                                        session.get().getSessionId());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
