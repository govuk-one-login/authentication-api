package uk.gov.di.orchestration.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.BaseFrontendRequest;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.orchestration.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;

public abstract class BaseFrontendHandler<T>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(BaseFrontendHandler.class);
    private static final String CLIENT_ID = "client_id";
    public static final String TXMA_AUDIT_ENCODED_HEADER = "txma-audit-encoded";
    private final Class<T> clazz;
    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientSessionService clientSessionService;
    protected final ClientService clientService;
    protected final AuthenticationService authenticationService;
    protected final Json objectMapper = SerializationService.getInstance();

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.clientService = clientService;
        this.authenticationService = authenticationService;
    }

    protected BaseFrontendHandler(Class<T> clazz, ConfigurationService configurationService) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
    }

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            RedisConnectionService redis) {
        this.clazz = clazz;
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService, redis);
        this.clientSessionService = new ClientSessionService(configurationService, redis);
        this.clientService = new DynamoClientService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
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

        String clientSessionId =
                getHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        onRequestReceived(clientSessionId);
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        Optional<ClientSession> clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            LOG.warn("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } else {
            attachSessionIdToLogs(session.get());
        }
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

        userContextBuilder.withClientSessionId(clientSessionId);

        var clientID =
                clientSession
                        .map(ClientSession::getAuthRequestParams)
                        .map(t -> t.get(CLIENT_ID))
                        .flatMap(v -> v.stream().findFirst());

        attachLogFieldToLogs(LogLineHelper.LogFieldName.CLIENT_ID, clientID.orElse(UNKNOWN));

        clientID.ifPresent(c -> userContextBuilder.withClient(clientService.getClient(c)));

        clientSession.ifPresent(userContextBuilder::withClientSession);

        session.map(Session::getEmailAddress)
                .map(authenticationService::getUserProfileFromEmail)
                .ifPresentOrElse(
                        userProfile ->
                                userContextBuilder
                                        .withUserProfile(userProfile)
                                        .withUserAuthenticated(true),
                        () -> {
                            if (request instanceof BaseFrontendRequest baseFrontendRequest)
                                userContextBuilder
                                        .withUserProfile(
                                                authenticationService.getUserProfileFromEmail(
                                                        baseFrontendRequest
                                                                .getEmail()
                                                                .toLowerCase(Locale.ROOT)))
                                        .withUserAuthenticated(false);
                        });

        userContextBuilder.withUserLanguage(matchSupportedLanguage(userLanguage));

        return handleRequestWithUserContext(input, context, request, userContextBuilder.build());
    }
}
