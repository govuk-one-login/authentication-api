package uk.gov.di.authentication.oidc.lambda;

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
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.TokenGeneratorHelper;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.buildCookieString;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

    private static final State STATE = new State();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final URI DEFAULT_LOGOUT_URI =
            URI.create("https://di-authentication-frontend.london.cloudapps.digital/signed-out");
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private LogoutHandler handler;
    private SignedJWT signedIDToken;
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL = "joe.bloggs@test.com";
    private final Session session = generateSession().setEmailAddress(EMAIL);

    @BeforeEach
    public void setUp() throws JOSEException {
        handler =
                new LogoutHandler(
                        configurationService,
                        sessionService,
                        dynamoClientService,
                        clientSessionService,
                        tokenValidationService,
                        dynamoService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
    }

    @Test
    public void shouldDeleteSessionAndRedirectToClientLogoutUriForValidLogoutRequest() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        when(dynamoService.getUserProfileByEmail(EMAIL)).thenReturn(generateUserProfile());
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
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        when(dynamoService.getUserProfileByEmail(EMAIL)).thenReturn(generateUserProfile());
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
    public void
            shouldRedirectToDefaultLogoutUriWithErrorMessageWhenClientSessionIdIsNotFoundInSession()
                    throws URISyntaxException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        event.setHeaders(Map.of(COOKIE, buildCookieString("invalid-client-session-id")));
        generateSessionFromCookie(session);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenIDTokenHintIsNotFoundInSession()
            throws URISyntaxException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedIDToken.serialize(),
                        "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));
        generateSessionFromCookie(session);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.INVALID_REQUEST_CODE, "id token does not exist in session");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenSubjectInIdTokenIsInvalid()
            throws URISyntaxException, JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", new Subject(), "http://localhost-rp", ecSigningKey);
        when(tokenValidationService.isTokenSignatureValid(signedJWT.serialize())).thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedJWT.serialize(),
                        "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));

        session.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        setupClientSessionToken(signedJWT);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid subject in id token");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
    }

    @Test
    public void
            shouldRedirectToDefaultLogoutUriWithErrorMessageWhenClientIsNotFoundInClientRegistry()
                    throws JOSEException, URISyntaxException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
        when(tokenValidationService.isTokenSignatureValid(signedJWT.serialize())).thenReturn(true);
        when(dynamoService.getUserProfileByEmail(EMAIL)).thenReturn(generateUserProfile());
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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.UNAUTHORIZED_CLIENT_CODE,
                        "client not found in client registry");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("state", STATE.getValue());
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
    }

    @Test
    public void
            shouldRedirectToDefaultLogoutUriWithErrorMessageWhenLogoutUriInRequestDoesNotMatchClientRegistry()
                    throws URISyntaxException {
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(dynamoService.getUserProfileByEmail(EMAIL)).thenReturn(generateUserProfile());
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
        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.INVALID_REQUEST_CODE,
                        "client registry does not contain post_logout_redirect_uri");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("state", STATE.getValue());
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
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
                        LocalDateTime.now(),
                        mock(VectorOfTrust.class));
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

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .setEmail(EMAIL)
                .setEmailVerified(true)
                .setPublicSubjectID(SUBJECT.getValue());
    }
}
