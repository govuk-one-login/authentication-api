package uk.gov.di.authentication.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1015;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1018;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public abstract class UserContextAwareHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserContextAwareHandler.class);

    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientSessionService clientSessionService;
    protected final ClientService clientService;

    private Session session;
    private ClientSession clientSession;
    private ClientRegistry clientRegistry;

    protected UserContextAwareHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    protected UserContextAwareHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.clientService = clientService;
    }

    protected abstract APIGatewayProxyResponseEvent handleRequestDelegate(
            APIGatewayProxyRequestEvent input, Context context);

    protected Session getSession() {
        return session;
    }

    protected ClientSession getClientSession() {
        return clientSession;
    }

    protected ClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    protected Optional<APIGatewayProxyResponseEvent> initializeUserContext(
            Map<String, String> headers, boolean initializeClientContext) {

        session = sessionService.getSessionFromRequestHeaders(headers).orElse(null);
        if (session == null) {
            LOGGER.error("Session cannot be found");
            return Optional.of(generateApiGatewayProxyErrorResponse(400, ERROR_1000));
        } else {
            LOGGER.info("{} processing request for session {}", getClass(), session.getSessionId());
        }

        if (!initializeClientContext) {
            return Optional.empty();
        }
        clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(headers).orElse(null);
        if (clientSession == null) {
            LOGGER.error(
                    "{} ClientSession not found for session {}",
                    getClass(),
                    session.getSessionId());
            return Optional.of(generateApiGatewayProxyErrorResponse(400, ERROR_1018));
        }

        clientRegistry = getClientRegistryForClientSession(clientSession);
        if (clientRegistry == null) {
            LOGGER.error(
                    "{} ClientRegistry not found for session {}",
                    getClass(),
                    session.getSessionId());
            return Optional.of(generateApiGatewayProxyErrorResponse(400, ERROR_1015));
        }
        return Optional.empty();
    }

    private ClientRegistry getClientRegistryForClientSession(ClientSession clientSession) {
        return clientSessionService
                .getClientIdForClientSession(clientSession)
                .flatMap(clientService::getClient)
                .orElse(null);
    }

    protected boolean isTestClientSession(ClientSession clientSession) {
        return clientSessionService
                .getClientIdForClientSession(clientSession)
                .flatMap(clientService::getClient)
                .map(this::isTestClient)
                .orElse(false);
    }

    private boolean isTestClient(ClientRegistry clientRegistry) {
        return clientRegistry.getScopes() != null && clientRegistry.getScopes().contains("test");
    }
}
