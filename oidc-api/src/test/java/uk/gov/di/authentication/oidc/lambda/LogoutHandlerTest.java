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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final LogoutService logoutService = mock(LogoutService.class);

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
    private Optional<String> audience;
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL = "joe.bloggs@test.com";
    private Session session;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(LogoutHandler.class);

    @AfterEach
    void tearDown() {
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
    void setUp() throws JOSEException, ParseException {
        handler =
                new LogoutHandler(
                        sessionService,
                        dynamoClientService,
                        clientSessionService,
                        tokenValidationService,
                        cloudwatchMetricsService,
                        logoutService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(logoutService.generateLogoutResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(new APIGatewayProxyResponseEvent());
        when(logoutService.generateErrorLogoutResponse(any(), any(), any(), any(), any()))
                .thenReturn(new APIGatewayProxyResponseEvent());
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
        SignedJWT idToken = SignedJWT.parse(signedIDToken.serialize());
        audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
    }

    @Nested
    class SessionExists {
        String idTokenHint;

        @BeforeEach
        void sessionExistsSetup() {
            session = generateSession().setEmailAddress(EMAIL);
            idTokenHint = signedIDToken.serialize();
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
        }

        @Test
        void shouldDeleteSessionAndRedirectToClientLogoutUriForValidLogoutRequest() {
            var idTokenHint = signedIDToken.serialize();

            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);

            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint", idTokenHint,
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                    "state", STATE.toString()));
            setupSessions();

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateLogoutResponse(
                            CLIENT_LOGOUT_URI,
                            Optional.of(STATE.toString()),
                            Optional.empty(),
                            event,
                            audience,
                            Optional.of(SESSION_ID));
            verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        }

        @Test
        void shouldNotThrowWhenTryingToDeleteClientSessionWhichHasExpired() {
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

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateLogoutResponse(
                            CLIENT_LOGOUT_URI,
                            Optional.of(STATE.toString()),
                            Optional.empty(),
                            event,
                            audience,
                            Optional.of(SESSION_ID));
            verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        }

        @Test
        void
                shouldDeleteSessionAndRedirectToDefaultLogoutUriForValidLogoutRequestWithNoQueryParams() {
            APIGatewayProxyRequestEvent event = generateRequestEvent(null);
            setupSessions();

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.empty(), event, Optional.empty(), Optional.of(SESSION_ID));
        }

        @Test
        void shouldRedirectToClientLogoutUriWhenNoCookieExists() {
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "id_token_hint",
                            idTokenHint,
                            "post_logout_redirect_uri",
                            CLIENT_LOGOUT_URI.toString(),
                            "state",
                            STATE.toString()));
            event.setRequestContext(contextWithSourceIp("123.123.123.123"));
            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateLogoutResponse(
                            CLIENT_LOGOUT_URI,
                            Optional.of(STATE.getValue()),
                            Optional.empty(),
                            event,
                            audience,
                            Optional.empty());
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void
                shouldRedirectToDefaultLogoutUriWithErrorMessageWhenClientSessionIdIsNotFoundInSession() {
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "id_token_hint",
                            idTokenHint,
                            "post_logout_redirect_uri",
                            CLIENT_LOGOUT_URI.toString(),
                            "state",
                            STATE.toString()));
            event.setRequestContext(contextWithSourceIp("123.123.123.123"));
            event.setHeaders(Map.of(COOKIE, buildCookieString("invalid-client-session-id")));
            generateSessionFromCookie(session);

            handler.handleRequest(event, context);

            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.empty(),
                            new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session"),
                            event,
                            Optional.empty(),
                            Optional.of(session.getSessionId()));
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenIDTokenHintIsNotFoundInSession() {
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint",
                                    idTokenHint,
                                    "post_logout_redirect_uri",
                                    CLIENT_LOGOUT_URI.toString()));
            generateSessionFromCookie(session);

            handler.handleRequest(event, context);

            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.empty(),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "id_token_hint does not exist in session"),
                            event,
                            Optional.empty(),
                            Optional.of(session.getSessionId()));
            verifyNoInteractions(cloudwatchMetricsService);
        }
    }

    @Nested
    class IdToken {
        @Test
        void shouldRedirectToDefaultLogoutUriForValidLogoutRequestWithNoTokenHint() {
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                    "state", STATE.toString()));

            handler.handleRequest(event, context);

            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.of(STATE.toString()),
                            event,
                            Optional.empty(),
                            Optional.empty());
        }

        @Test
        void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenSignatureIdTokenIsInvalid()
                throws JOSEException {
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            SignedJWT signedJWT =
                    TokenGeneratorHelper.generateIDToken(
                            "invalid-client-id",
                            new Subject(),
                            "http://localhost-rp",
                            ecSigningKey);
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint", signedJWT.serialize(),
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString()));

            handler.handleRequest(event, context);

            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.empty(),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "unable to validate id_token_hint"),
                            event,
                            Optional.empty(),
                            Optional.empty());
            verifyNoInteractions(cloudwatchMetricsService);
        }
    }

    @Nested
    class ClientIdAndPostLogoutRedirectUri {

        @Test
        void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenClientIsNotFoundInClientRegistry()
                throws JOSEException, ParseException {
            session = generateSession().setEmailAddress(EMAIL);
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            SignedJWT signedJWT =
                    TokenGeneratorHelper.generateIDToken(
                            "invalid-client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
            when(tokenValidationService.isTokenSignatureValid(signedJWT.serialize()))
                    .thenReturn(true);
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint", signedJWT.serialize(),
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                    "state", STATE.toString()));
            session.getClientSessions().add(CLIENT_SESSION_ID);
            generateSessionFromCookie(session);
            setupClientSessionToken(signedJWT);

            handler.handleRequest(event, context);

            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                            event,
                            signedJWT.getJWTClaimsSet().getAudience().stream().findFirst(),
                            Optional.empty());
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void
                shouldRedirectToDefaultLogoutUriWithErrorMessageWhenLogoutUriInRequestDoesNotMatchClientRegistry()
                        throws JOSEException, ParseException {
            session = generateSession().setEmailAddress(EMAIL);
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            SignedJWT signedJWT =
                    TokenGeneratorHelper.generateIDToken(
                            "client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
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
            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"),
                            event,
                            signedJWT.getJWTClaimsSet().getAudience().stream().findFirst(),
                            Optional.of(session.getSessionId()));
            verifyNoInteractions(cloudwatchMetricsService);
        }
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
                        List.of(mock(VectorOfTrust.class)),
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
                                        List.of(VectorOfTrust.getDefaults()),
                                        "client_name")));
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }
}
