package uk.gov.di.authentication.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.OrchestrationUserSession;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;

public abstract class BaseOrchestrationFrontendHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(BaseFrontendHandler.class);
    private static final String CLIENT_ID = "client_id";
    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientSessionService clientSessionService;

    protected BaseOrchestrationFrontendHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
    }

    protected BaseOrchestrationFrontendHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                getSegmentName() + getClass().getSimpleName(),
                () -> validateAndHandleRequest(input, context));
    }

    public abstract APIGatewayProxyResponseEvent handleRequestWithUserSession(
            APIGatewayProxyRequestEvent input,
            Context context,
            final OrchestrationUserSession orchestrationUserSession);

    private APIGatewayProxyResponseEvent validateAndHandleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();

        var session = sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
        if (Objects.isNull(session)) {
            LOG.warn("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } else {
            attachSessionIdToLogs(session);
        }
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        OrchestrationUserSession.Builder userSessionBuilder =
                OrchestrationUserSession.builder(session);

        String clientSessionId =
                getHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        userSessionBuilder.withClientSessionId(clientSessionId);

        Optional<ClientSession> clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());
        userSessionBuilder.withClientSession(clientSession.orElse(null));

        var clientID =
                clientSession
                        .map(ClientSession::getAuthRequestParams)
                        .map(t -> t.get(CLIENT_ID))
                        .flatMap(v -> v.stream().findFirst());
        attachLogFieldToLogs(LogLineHelper.LogFieldName.CLIENT_ID, clientID.orElse(UNKNOWN));
        userSessionBuilder.withClientId(clientID.orElse(null));

        return handleRequestWithUserSession(input, context, userSessionBuilder.build());
    }

    protected abstract String getSegmentName();
}
