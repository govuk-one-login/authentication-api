package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.TokenGeneratorHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ResponseHeaders;
import uk.gov.di.entity.Session;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.helpers.CookieHelper.buildCookieString;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);

    private static final State STATE = new State();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final URI DEFAULT_LOGOUT_URI =
            URI.create("https://di-authentication-frontend.london.cloudapps.digital/signed-out");
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private LogoutHandler handler;
    private SignedJWT signedIDToken;
    private final Session session = generateSession();

    @BeforeEach
    public void setUp() throws JOSEException {
        handler =
                new LogoutHandler(
                        configurationService,
                        sessionService,
                        dynamoClientService,
                        clientSessionService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id", new Subject(), "http://localhost-rp", ecSigningKey);
    }

    @Test
    public void shouldDeleteSessionAndRedirectToClientLogoutUriForValidLogoutRequest() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedIDToken.serialize(),
                        "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                        "state", STATE.toString()));
        session.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        setupClientSessionToken(signedIDToken);
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        verify(sessionService, times(1)).deleteSessionFromRedis(SESSION_ID);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));
    }

    @Test
    public void shouldNotReturnStateWhenStateIsNotSentInRequest() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint",
                        signedIDToken.serialize(),
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString()));
        session.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        setupClientSessionToken(signedIDToken);
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(sessionService, times(1)).deleteSessionFromRedis(SESSION_ID);
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI.toString()));
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWhenNoCookieExists() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI + "?state=" + STATE));
        verify(sessionService, times(0)).deleteSessionFromRedis(SESSION_ID);
    }

    @Test
    public void shouldThrowWhenClientSessionIdIsNotFoundInSession() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        event.setHeaders(Map.of(COOKIE, buildCookieString("invalid-client-session-id")));
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
    public void shouldThrowWhenIDTokenHintIsNotFoundInSession() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedIDToken.serialize(),
                        "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                        "state", STATE.toString()));
        generateSessionFromCookie(session);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(format("ID Token does not exist for Session: %s", session.getSessionId())));
        verify(sessionService, times(0)).deleteSessionFromRedis(SESSION_ID);
    }

    @Test
    public void shouldThrowWhenClientIsNotFoundInClientRegistry() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", new Subject(), "http://localhost-rp", ecSigningKey);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedJWT.serialize(),
                        "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                        "state", STATE.toString()));

        session.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        setupClientSessionToken(signedJWT);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(
                        format(
                                "Client not found in ClientRegistry for ClientID: %s",
                                "invalid-client-id")));
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWhenLogoutUriInRequestDoesNotMatchClientRegistry() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedIDToken.serialize(),
                        "post_logout_redirect_uri", "http://localhost/invalidlogout",
                        "state", STATE.toString()));
        session.getClientSessions().add(CLIENT_SESSION_ID);
        setupClientSessionToken(signedIDToken);
        generateSessionFromCookie(session);
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI + "?state=" + STATE));
        verify(sessionService, times(1)).deleteSessionFromRedis(SESSION_ID);
    }

    private void setupClientSessionToken(JWT idToken) {
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
        clientSession.setIdTokenHint(idToken.serialize());
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID)).thenReturn(clientSession);
    }

    private Session generateSession() {
        return new Session(SESSION_ID).addClientSession(CLIENT_SESSION_ID);
    }

    private void generateSessionFromCookie(Session session) {
        when(sessionService.getSessionFromSessionCookie(anyMap())).thenReturn(Optional.of(session));
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .setClientID("client-id")
                .setClientName("client-one")
                .setPublicKey("public-key")
                .setContacts(singletonList("contact-1"))
                .setPostLogoutRedirectUrls(singletonList(CLIENT_LOGOUT_URI.toString()))
                .setScopes(singletonList("openid"))
                .setRedirectUrls(singletonList("http://localhost/redirect"));
    }
}
