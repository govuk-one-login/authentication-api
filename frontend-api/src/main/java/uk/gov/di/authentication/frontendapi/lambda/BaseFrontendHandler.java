package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.UserWithEmailRequest;
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

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public abstract class BaseFrontendHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(BaseFrontendHandler.class);
    protected final ConfigurationService configurationService;
    protected final SessionService sessionService;
    protected final ClientSessionService clientSessionService;
    protected final ClientService clientService;
    protected final AuthenticationService authenticationService;
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    protected BaseFrontendHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.clientService = clientService;
        this.authenticationService = authenticationService;
    }

    protected BaseFrontendHandler(ConfigurationService configurationService) {
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

    public abstract APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input, Context context, UserContext userContext);

    private APIGatewayProxyResponseEvent validateAndHandleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        Optional<ClientSession> clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());
        if (session.isPresent()) {
            UserContext.Builder userContextBuilder = UserContext.builder(session.get());
            clientSession.ifPresent(
                    cs ->
                            userContextBuilder.withClient(
                                    clientService.getClient(
                                            cs.getAuthRequestParams().get("client_id").stream()
                                                    .findFirst()
                                                    .orElseThrow())));
            session.ifPresent(
                    s ->
                            userContextBuilder.withUserProfile(
                                    authenticationService.getUserProfileFromEmail(
                                            s.getEmailAddress())));
            ;
            session.map(Session::getEmailAddress)
                    .ifPresentOrElse(
                            email ->
                                    userContextBuilder
                                            .withUserProfile(
                                                    authenticationService.getUserProfileFromEmail(
                                                            email))
                                            .withUserAuthenticated(true),
                            () -> {
                                try {
                                    UserWithEmailRequest request =
                                            objectMapper.readValue(
                                                    input.getBody(), UserWithEmailRequest.class);
                                    userContextBuilder
                                            .withUserProfile(
                                                    authenticationService.getUserProfileFromEmail(
                                                            request.getEmail()))
                                            .withUserAuthenticated(false);
                                } catch (JsonProcessingException e) {
                                    LOG.warn("Request didn't contain an e-mail address");
                                }
                            });

            return handleRequestWithUserContext(input, context, userContextBuilder.build());
        } else {
            LOG.error("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
    }
}
