package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public abstract class BaseFrontendHandler<T>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(BaseFrontendHandler.class);
    private static final String CLIENT_ID = "client_id";
    private final Class<T> clazz;
    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientSessionService clientSessionService;
    protected final ClientService clientService;
    protected final AuthenticationService authenticationService;
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

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
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input).orElseGet(() -> validateAndHandleRequest(input, context));
    }

    public void onRequestReceived(Context context) {}

    public void onRequestValidationError(Context context) {}

    public abstract APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            final T request,
            final UserContext userContext);

    private APIGatewayProxyResponseEvent validateAndHandleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        onRequestReceived(context);
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        Optional<ClientSession> clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            LOG.error("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        final T request;
        try {
            request = objectMapper.readValue(input.getBody(), clazz);
        } catch (JsonProcessingException | ConstraintViolationException e) {
            LOG.error("Request is missing parameters.");
            onRequestValidationError(context);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        UserContext.Builder userContextBuilder = UserContext.builder(session.get());

        clientSession
                .map(ClientSession::getAuthRequestParams)
                .map(m -> m.get(CLIENT_ID))
                .flatMap(v -> v.stream().findFirst())
                .ifPresent(c -> userContextBuilder.withClient(clientService.getClient(c)));

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

        return handleRequestWithUserContext(input, context, request, userContextBuilder.build());
    }
}
