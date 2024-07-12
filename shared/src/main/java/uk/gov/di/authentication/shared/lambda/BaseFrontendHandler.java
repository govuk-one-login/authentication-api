package uk.gov.di.authentication.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueOrElse;

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
    protected boolean loadUserCredentials = false;

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

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            boolean loadUserCredentials) {
        this(
                clazz,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.loadUserCredentials = loadUserCredentials;
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

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            boolean loadUserCredentials) {
        this(clazz, configurationService);
        this.loadUserCredentials = loadUserCredentials;
    }

    protected BaseFrontendHandler(
            Class<T> clazz,
            ConfigurationService configurationService,
            boolean loadUserCredentials,
            RedisConnectionService redis) {
        this(clazz, configurationService, redis);
        this.loadUserCredentials = loadUserCredentials;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "frontend-api::" + getClass().getSimpleName(),
                () -> validateAndHandleRequest(input, context));
    }

    public void onRequestReceived(String clientSessionId, String txmaAuditEncoded) {}

    public void onRequestValidationError(String clientSessionId, String txmaAuditEncoded) {}

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
        String txmaAuditEncoded =
                getHeaderValueOrElse(input.getHeaders(), TXMA_AUDIT_ENCODED_HEADER, null);

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());

        if (session.isEmpty()) {
            LOG.warn("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } else {
            attachSessionIdToLogs(session.get());
        }

        UserContext.Builder userContextBuilder = UserContext.builder(session.get());
        userContextBuilder.withTxmaAuditEvent(txmaAuditEncoded);

        onRequestReceived(clientSessionId, txmaAuditEncoded);

        Optional<ClientSession> clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());

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
            onRequestValidationError(clientSessionId, txmaAuditEncoded);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

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
                            if (request instanceof BaseFrontendRequest)
                                userContextBuilder
                                        .withUserProfile(
                                                authenticationService.getUserProfileFromEmail(
                                                        ((BaseFrontendRequest) request)
                                                                .getEmail()
                                                                .toLowerCase(Locale.ROOT)))
                                        .withUserAuthenticated(false);
                        });

        if (loadUserCredentials) {
            session.map(Session::getEmailAddress)
                    .map(authenticationService::getUserCredentialsFromEmail)
                    .ifPresent(
                            userCredentials ->
                                    userContextBuilder.withUserCredentials(
                                            Optional.of(userCredentials)));
        }

        userContextBuilder.withUserLanguage(matchSupportedLanguage(userLanguage));

        userContextBuilder.withTxmaAuditEvent(txmaAuditEncoded);

        return handleRequestWithUserContext(input, context, request, userContextBuilder.build());
    }
}
