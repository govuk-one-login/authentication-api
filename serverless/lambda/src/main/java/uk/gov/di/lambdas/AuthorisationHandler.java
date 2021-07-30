package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.SessionService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorisationHandler.class);

    private final ClientService clientService;
    private final SessionService sessionService;
    private final ConfigurationService configurationService;
    private final ClientSessionService clientSessionService;

    private interface ResponseHeaders {
        String LOCATION = "Location";
        String SET_COOKIE = "Set-Cookie";
    }

    public AuthorisationHandler(
            ClientService clientService,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService) {
        this.clientService = clientService;
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
    }

    public AuthorisationHandler() {
        configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOGGER.info("Received authentication request");
        try {
            Map<String, List<String>> queryStringMultiValuedMap =
                    input.getQueryStringParameters().entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            entry -> entry.getKey(),
                                            entry -> List.of(entry.getValue())));
            var authRequest = AuthenticationRequest.parse(queryStringMultiValuedMap);

            Optional<ErrorObject> error =
                    clientService.getErrorForAuthorizationRequest(authRequest);

            return error.map(e -> errorResponse(authRequest, e))
                    .orElseGet(
                            () ->
                                    getOrCreateSessionAndRedirect(
                                            queryStringMultiValuedMap,
                                            sessionService.getSessionFromSessionCookie(
                                                    input.getHeaders()),
                                            authRequest.getClientID()));
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            response.setStatusCode(400);
            response.setBody("Cannot parse authentication request");

            return response;
        }
    }

    private APIGatewayProxyResponseEvent getOrCreateSessionAndRedirect(
            Map<String, List<String>> authRequest,
            Optional<Session> existingSession,
            ClientID clientId) {

        /*
           For a user without an existing Session proceed to login
        */
        if (existingSession.isEmpty()) {
            return createSessionAndRedirect(authRequest, clientId);
        }

        /*
           For a user with an existing Session = SSO scenario
        */
        Session session = existingSession.get();
        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(authRequest, LocalDateTime.now()));
        updateSessionId(session, clientId, clientSessionID);
        return redirect(session, clientSessionID);
    }

    private void updateSessionId(Session session, ClientID clientId, String clientSessionID) {
        String oldSessionId = session.getSessionId();
        sessionService.updateSessionId(session);
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Updated session id from {} to {} for client {} - client session id = {}",
                oldSessionId,
                session.getSessionId(),
                clientId.getValue(),
                clientSessionID);

        sessionService.save(session);
        LOGGER.info("Session saved successfully {}", session.getSessionId());
    }

    private APIGatewayProxyResponseEvent createSessionAndRedirect(
            Map<String, List<String>> authRequest, ClientID clientId) {
        Session session = sessionService.createSession();

        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(authRequest, LocalDateTime.now()));
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Created session {} for client {} - client session id = {}",
                session.getSessionId(),
                clientId.getValue(),
                clientSessionID);
        sessionService.save(session);
        LOGGER.info("Session saved successfully {}", session.getSessionId());
        return redirect(session, clientSessionID);
    }

    private APIGatewayProxyResponseEvent redirect(Session session, String clientSessionID) {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of(
                                ResponseHeaders.LOCATION,
                                configurationService.getLoginURI().toString(),
                                ResponseHeaders.SET_COOKIE,
                                buildCookieString(
                                        session,
                                        configurationService.getSessionCookieMaxAge(),
                                        configurationService.getSessionCookieAttributes(),
                                        clientSessionID,
                                        configurationService.getDomainName())));
    }

    private APIGatewayProxyResponseEvent errorResponse(
            AuthorizationRequest authRequest, ErrorObject errorObject) {
        AuthenticationErrorResponse error =
                new AuthenticationErrorResponse(
                        authRequest.getRedirectionURI(),
                        errorObject,
                        authRequest.getState(),
                        authRequest.getResponseMode());

        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of("Location", error.toURI().toString()));
    }

    private String buildCookieString(
            Session session,
            Integer maxAge,
            String attributes,
            String clientSessionID,
            String domain) {
        return format(
                "%s=%s.%s; Max-Age=%d; Domain=%s; %s",
                "gs", session.getSessionId(), clientSessionID, maxAge, domain, attributes);
    }
}
