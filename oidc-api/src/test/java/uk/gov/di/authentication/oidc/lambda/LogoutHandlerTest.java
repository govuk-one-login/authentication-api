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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatcher;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.services.BackChannelLogoutService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final BackChannelLogoutService backChannelLogoutService =
            mock(BackChannelLogoutService.class);

    private static final State STATE = new State();
    private static final String COOKIE = "Cookie";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;
    private static final URI DEFAULT_LOGOUT_URI =
            URI.create("https://di-authentication-frontend.london.cloudapps.digital/signed-out");
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private LogoutHandler handler;
    private SignedJWT signedIDToken;
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL = "joe.bloggs@test.com";
    private Session session;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(LogoutHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        SESSION_ID,
                                        CLIENT_SESSION_ID,
                                        PERSISTENT_SESSION_ID,
                                        SUBJECT.toString()))));
    }

    @BeforeEach
    public void setUp() throws JOSEException {
        handler =
                new LogoutHandler(
                        configurationService,
                        sessionService,
                        dynamoClientService,
                        clientSessionService,
                        tokenValidationService,
                        auditService,
                        cloudwatchMetricsService,
                        backChannelLogoutService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
        session = generateSession().setEmailAddress(EMAIL);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
    }

    @Test
    public void shouldDeleteSessionAndRedirectToClientLogoutUriForValidLogoutRequest() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", signedIDToken.serialize(),
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                "state", STATE.toString()));
        setupSessions();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verifySessions();
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));

        verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void shouldNotThrowWhenTryingToDeleteClientSessionWhichHasExpired() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        var event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", signedIDToken.serialize(),
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                "state", STATE.toString()));
        setupSessions();
        session.getClientSessions().add("expired-client-session-id");

        var response = handler.handleRequest(event, context);

        verifySessions();
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));

        verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void
            shouldDeleteSessionAndRedirectToDefaultLogoutUriForValidLogoutRequestWithHintOnly() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(Map.of("id_token_hint", signedIDToken.serialize()));
        setupSessions();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verifySessions();
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI.toString()));

        verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void
            shouldDeleteSessionAndRedirectToDefaultLogoutUriForValidLogoutRequestWithLogoutURIOnly() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of("post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));
        setupSessions();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verifySessions();
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI.toString()));

        verify(cloudwatchMetricsService).incrementLogout(Optional.empty());
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void
            shouldDeleteSessionAndRedirectToDefaultLogoutUriForValidLogoutRequestWithNoQueryParams() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event = generateRequestEvent(null);
        setupSessions();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verifySessions();
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI.toString()));

        verify(cloudwatchMetricsService).incrementLogout(Optional.empty());
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void shouldNotReturnStateWhenStateIsNotSentInRequest() {
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", signedIDToken.serialize(),
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));
        generateSessionFromCookie(session);
        setupClientSessionToken(signedIDToken);
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        verify(sessionService, times(1)).deleteSessionFromRedis(SESSION_ID);
        verify(clientSessionService).deleteClientSessionFromRedis(CLIENT_SESSION_ID);
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI.toString()));

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
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
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI + "?state=" + STATE));
        verify(sessionService, times(0)).deleteSessionFromRedis(SESSION_ID);

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
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
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
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

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenIDTokenHintIsNotFoundInSession()
            throws URISyntaxException {
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", signedIDToken.serialize(),
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));
        generateSessionFromCookie(session);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.INVALID_REQUEST_CODE, "unable to validate id_token_hint");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenSignaturenIdTokenIsInvalid()
            throws URISyntaxException, JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", new Subject(), "http://localhost-rp", ecSigningKey);
        when(tokenValidationService.isTokenSignatureValid(signedJWT.serialize())).thenReturn(false);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", signedJWT.serialize(),
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));

        session.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(session);
        setupClientSessionToken(signedJWT);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.INVALID_REQUEST_CODE, "unable to validate id_token_hint");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
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
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
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
                new ErrorObject(OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("state", STATE.getValue());
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "invalid-client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    public void
            shouldRedirectToDefaultLogoutUriWithErrorMessageWhenLogoutUriInRequestDoesNotMatchClientRegistry()
                    throws URISyntaxException {
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
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

        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        SESSION_ID,
                        "client-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    private void setupClientSessionToken(JWT idToken) {
        ClientSession clientSession =
                new ClientSession(
                        Map.of(
                                "client_id",
                                List.of("client-id"),
                                "redirect_uri",
                                List.of("http://localhost:8080"),
                                "scope",
                                List.of("email,openid,profile"),
                                "response_type",
                                List.of("code"),
                                "state",
                                List.of("some-state")),
                        LocalDateTime.now(),
                        mock(VectorOfTrust.class),
                        "client_name");
        clientSession.setIdTokenHint(idToken.serialize());
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private Session generateSession() {
        return new Session(SESSION_ID).addClientSession(CLIENT_SESSION_ID);
    }

    private void generateSessionFromCookie(Session session) {
        when(sessionService.getSessionFromSessionCookie(anyMap())).thenReturn(Optional.of(session));
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .withClientID("client-id")
                .withClientName("client-one")
                .withPublicKey("public-key")
                .withContacts(singletonList("contact-1"))
                .withPostLogoutRedirectUrls(singletonList(CLIENT_LOGOUT_URI.toString()))
                .withScopes(singletonList("openid"))
                .withRedirectUrls(singletonList("http://localhost/redirect"));
    }

    private static String buildCookieString(String clientSessionId) {
        return format(
                "gs=%s.%s; %s=%s; Max-Age=%d; %s",
                SESSION_ID,
                clientSessionId,
                CookieHelper.PERSISTENT_COOKIE_NAME,
                PERSISTENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;");
    }

    private static APIGatewayProxyRequestEvent generateRequestEvent(
            Map<String, String> queryStringParameters) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        if (queryStringParameters != null) {
            event.setQueryStringParameters(queryStringParameters);
        }
        return event;
    }

    private void setupSessions() {
        setUpClientSession("client-session-id-2", "client-id-2");
        setUpClientSession("client-session-id-3", "client-id-3");
        generateSessionFromCookie(session);
        setupClientSessionToken(signedIDToken);
    }

    private void setUpClientSession(String clientSessionId, String clientId) {
        session.getClientSessions().add(clientSessionId);
        when(clientSessionService.getClientSession(clientSessionId))
                .thenReturn(
                        Optional.of(
                                new ClientSession(
                                        Map.of("client_id", List.of(clientId)),
                                        LocalDateTime.now(),
                                        VectorOfTrust.getDefaults(),
                                        "client_name")));
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }

    private void verifySessions() {
        verify(sessionService).deleteSessionFromRedis(SESSION_ID);

        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-2")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-3")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));

        verify(clientSessionService).deleteClientSessionFromRedis(CLIENT_SESSION_ID);
        verify(clientSessionService).deleteClientSessionFromRedis("client-session-id-2");
        verify(clientSessionService).deleteClientSessionFromRedis("client-session-id-3");
    }

    public static ArgumentMatcher<ClientRegistry> withClientId(String clientId) {
        return new ArgumentMatcher<>() {
            @Override
            public boolean matches(ClientRegistry argument) {
                return clientId.equals(argument.getClientID());
            }

            @Override
            public String toString() {
                return "a ClientRegistry with client_id " + clientId;
            }
        };
    }
}
