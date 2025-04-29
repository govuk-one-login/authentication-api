package uk.gov.di.orchestration.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.orchestration.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeadersOpt;

public abstract class BaseFrontendHandler<T>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(BaseFrontendHandler.class);
    private static final String CLIENT_ID = "client_id";
    private final Class<T> clazz;
    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientService clientService;
    protected final AuthenticationService authenticationService;
    protected final Json objectMapper = SerializationService.getInstance();
    protected final OrchSessionService orchSessionService;
    protected final OrchClientSessionService orchClientSessionService;

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientService = clientService;
        this.authenticationService = authenticationService;
        this.orchSessionService = orchSessionService;
        this.orchClientSessionService = orchClientSessionService;
    }

    protected BaseFrontendHandler(Class<T> clazz, ConfigurationService configurationService) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
    }

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            RedisConnectionService redis) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService, redis);
        this.clientService = new DynamoClientService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "frontend-api::" + getClass().getSimpleName(),
                () -> validateAndHandleRequest(input, context));
    }

    public void onRequestReceived(String clientSessionId) {}

    public void onRequestValidationError(String clientSessionId) {}

    public abstract APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            final T request,
            final UserContext userContext);

    private APIGatewayProxyResponseEvent validateAndHandleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        String sessionId;
        var sessionIdOpt =
                getHeaderValueFromHeadersOpt(
                        input.getHeaders(),
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (sessionIdOpt.isEmpty()) {
            LOG.warn("Session ID was not found in request headers");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        sessionId = sessionIdOpt.get();
        String clientSessionId =
                getHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        onRequestReceived(clientSessionId);
        Optional<Session> session = sessionService.getSession(sessionId);
        var orchClientSession =
                orchClientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());

        if (session.isEmpty()) {
            LOG.warn("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }

        Optional<OrchSessionItem> orchSession = orchSessionService.getSession(sessionId);
        if (orchSession.isEmpty()) {
            LOG.warn("Orch session not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        attachSessionIdToLogs(sessionId);

        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        Optional<String> userLanguage =
                getUserLanguageFromRequestHeaders(input.getHeaders(), configurationService);
        final T request;
        try {
            request = objectMapper.readValue(input.getBody(), clazz);
        } catch (JsonException e) {
            LOG.warn("Request is missing parameters.");
            onRequestValidationError(clientSessionId);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        UserContext.Builder userContextBuilder = UserContext.builder(session.get());

        userContextBuilder.withSessionId(sessionId).withClientSessionId(clientSessionId);
        userContextBuilder.withOrchSession(orchSession.get());

        var clientID =
                orchClientSession
                        .map(OrchClientSessionItem::getAuthRequestParams)
                        .map(t -> t.get(CLIENT_ID))
                        .flatMap(v -> v.stream().findFirst());

        attachLogFieldToLogs(LogLineHelper.LogFieldName.CLIENT_ID, clientID.orElse(UNKNOWN));

        clientID.ifPresent(c -> userContextBuilder.withClient(clientService.getClient(c)));

        orchClientSession.ifPresent(userContextBuilder::withOrchClientSession);

        userContextBuilder.withUserLanguage(matchSupportedLanguage(userLanguage));

        return handleRequestWithUserContext(input, context, request, userContextBuilder.build());
    }
}
