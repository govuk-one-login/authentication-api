package uk.gov.di.orchestration.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.OrchestrationUserSession;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeadersOpt;

public abstract class BaseOrchestrationFrontendHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(BaseOrchestrationFrontendHandler.class);
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
        var sessionIdOpt =
                getHeaderValueFromHeadersOpt(
                        input.getHeaders(),
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (sessionIdOpt.isEmpty()) {
            LOG.warn("Session ID was not found in request headers");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        var sessionId = sessionIdOpt.get();
        var clientSessionIdOpt =
                getHeaderValueFromHeadersOpt(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        var sessionOpt = sessionService.getSession(sessionId);
        if (sessionOpt.isEmpty()) {
            LOG.warn("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        var clientSession = clientSessionIdOpt.flatMap(clientSessionService::getClientSession);

        attachSessionIdToLogs(sessionId);
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        OrchestrationUserSession.Builder userSessionBuilder =
                OrchestrationUserSession.builder(sessionOpt.get())
                        .withSessionId(sessionId)
                        .withClientSessionId(clientSessionIdOpt.orElse(null))
                        .withClientSession(clientSession.orElse(null));

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
