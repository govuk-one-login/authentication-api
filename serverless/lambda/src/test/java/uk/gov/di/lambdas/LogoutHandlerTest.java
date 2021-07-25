package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.IDTokenGenerator;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final URI DEFAULT_LOGOUT_URI =
            URI.create("https://di-authentication-frontend.london.cloudapps.digital/signed-out");
    private LogoutHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new LogoutHandler(configurationService, sessionService, dynamoClientService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
    }

    @Test
    public void shouldDeleteSessionAndRedirectToClientLogoutUri() throws JOSEException {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        SignedJWT signedJWT =
                IDTokenGenerator.generateIDToken(
                        "client-id", new Subject(), "http://localhost-rp", signingKey);
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Session session = generateSession(CLIENT_SESSION_ID);
        session.getClientSessions().get(CLIENT_SESSION_ID).setIdTokenHint(signedJWT.serialize());
        generateSessionFromCookie(session);
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedJWT.serialize(),
                        "post_logout_redirect_uri", "http://localhost/logout",
                        "state", state.toString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo("http://localhost/logout"));
    }

    @Test
    public void shouldDeleteSessionAndRedirectToDefaultLogoutUriWhenNoCookieExists() {
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        "http://localhost:8000/logout",
                        "state",
                        state.toString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(DEFAULT_LOGOUT_URI.toString()));
        verify(sessionService, times(0)).deleteSessionFromRedis(SESSION_ID);
    }

    @Test
    public void shouldThrowWhenClientSessionIdIsNotFoundInSession() {
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        "http://localhost:8000/logout",
                        "state",
                        state.toString()));
        event.setHeaders(Map.of(COOKIE, buildCookieString("invalid-client-session-id")));
        Session session = generateSession(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(
                        format(
                                "Client Session ID does not exist in Session: %s",
                                session.getSessionId())));
    }

    @Test
    public void shouldThrowWhenIDTokenHintIsNotFoundInSession() throws JOSEException {
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        SignedJWT signedJWT =
                IDTokenGenerator.generateIDToken(
                        "client-id", new Subject(), "http://localhost-rp", signingKey);
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Session session = generateSession(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedJWT.serialize(),
                        "post_logout_redirect_uri", "http://localhost:8000/logout",
                        "state", state.toString()));

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(format("ID Token does not exist for Session: %s", session.getSessionId())));
    }

    private Session generateSession(String clientSessionID) {
        ClientSession clientSession =
                new ClientSession(
                        Map.of(
                                "client_id",
                                List.of("a-client-id"),
                                "redirect_uri",
                                List.of("http://localhost:8080"),
                                "scope",
                                List.of("email,openid,profile"),
                                "response_type",
                                List.of("code"),
                                "state",
                                List.of("some-state")),
                        LocalDateTime.now());
        return new Session(SESSION_ID).setClientSession(clientSessionID, clientSession);
    }

    private void generateSessionFromCookie(Session session) {
        when(sessionService.getSessionFromSessionCookie(anyMap())).thenReturn(Optional.of(session));
    }

    private String buildCookieString(String clientSessionID) {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, clientSessionID, 1800, "Secure; HttpOnly;");
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .setClientID("client-id")
                .setClientName("client-one")
                .setPublicKey("public-key")
                .setContacts(singletonList("contact-1"))
                .setPostLogoutRedirectUrls(singletonList("http://localhost/logout"))
                .setScopes(singletonList("openid"))
                .setRedirectUrls(singletonList("http://localhost/redirect"));
    }
}
