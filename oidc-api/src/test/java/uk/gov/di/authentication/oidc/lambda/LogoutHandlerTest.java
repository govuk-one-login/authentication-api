package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
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
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
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
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
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
    private uk.gov.di.orchestration.shared.entity.Session session;

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
                        tokenValidationService,
                        cloudwatchMetricsService,
                        logoutService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(logoutService.generateLogoutResponse(any(), any(), any(), any(), any()))
                .thenReturn(new APIGatewayProxyResponseEvent());
        when(logoutService.generateErrorLogoutResponse(any(), any(), any(), any()))
                .thenReturn(new APIGatewayProxyResponseEvent());
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id",
                        SUBJECT,
                        "http://localhost-rp",
                        "id-token-client-session-id",
                        ecSigningKey);
        SignedJWT idToken = SignedJWT.parse(signedIDToken.serialize());
        audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
    }

    @Nested
    class Session {
        String idTokenHint;

        @BeforeEach
        void sessionExistsSetup() {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
            idTokenHint = signedIDToken.serialize();
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
        }

        @Test
        void shouldDeleteSessionAndRedirectToClientLogoutUriForValidLogoutRequest()
                throws ParseException {
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
                            getAuditUserWhenCookieAndIdTokenHint(event, signedIDToken),
                            audience,
                            Optional.of(SUBJECT.getValue()));
            verify(cloudwatchMetricsService).incrementLogout(Optional.of("client-id"));
        }

        @Test
        void shouldNotThrowWhenTryingToDeleteClientSessionWhichHasExpired() throws ParseException {
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
            var event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint", idTokenHint,
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
                            getAuditUserWhenCookieAndIdTokenHint(event, signedIDToken),
                            audience,
                            Optional.of(SUBJECT.getValue()));
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
                            Optional.empty(),
                            getAuditUserWhenCookieAndNoIdTokenHint(event),
                            Optional.empty());
        }

        @Test
        void shouldRedirectToClientLogoutUriWhenNoCookieExists() throws ParseException {
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
                            getAuditUserWhenIdTokenHintAndNoCookie(event, signedIDToken),
                            audience,
                            Optional.of(SUBJECT.getValue()));
            verifyNoInteractions(cloudwatchMetricsService);
        }
    }

    @Nested
    class IdToken {
        @Test
        void shouldRedirectToDefaultLogoutUriForValidLogoutRequestWithNoTokenHint() {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                    "state", STATE.toString()));
            session.getClientSessions().add(CLIENT_SESSION_ID);
            generateSessionFromCookie(session);

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.of(STATE.toString()),
                            getAuditUserWhenCookieAndNoIdTokenHint(event),
                            Optional.empty());
        }

        @Test
        void
                shouldNotTryToDeleteSessionWhenSessionDoesNotExistWhileValidLogoutRequestWithNoTokenHint() {
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                    "state", STATE.toString()));

            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.of(STATE.toString()),
                            getAuditUserWhenNoCookie(event),
                            Optional.empty());
        }

        @Test
        void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenSignatureIdTokenIsInvalid()
                throws JOSEException {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
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
            session.getClientSessions().add(CLIENT_SESSION_ID);
            generateSessionFromCookie(session);

            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.empty(),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "unable to validate id_token_hint"),
                            getAuditUserWhenCookieAndNoIdTokenHint(event),
                            Optional.empty());
            verifyNoInteractions(cloudwatchMetricsService);
        }
    }

    @Nested
    class ClientIdAndPostLogoutRedirectUri {

        @Test
        void shouldRedirectToDefaultLogoutUriWithErrorMessageWhenClientIsNotFoundInClientRegistry()
                throws JOSEException, ParseException {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
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

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                            getAuditUserWhenCookieAndNoIdTokenHint(event),
                            signedJWT.getJWTClaimsSet().getAudience().stream().findFirst());
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void
                shouldNotTryToDeleteSessionWhenSessionDoesNotExistWhileClientIsNotFoundInClientRegistry()
                        throws JOSEException, ParseException {
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

            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                            getAuditUserWhenCookieAndNoIdTokenHint(event),
                            signedJWT.getJWTClaimsSet().getAudience().stream().findFirst());
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void shouldRedirectToDefaultUriWhenLogoutRedirectUriIsMissing() throws ParseException {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
            var idTokenHint = signedIDToken.serialize();

            session.getClientSessions().add(CLIENT_SESSION_ID);
            generateSessionFromCookie(session);
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);

            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of("id_token_hint", idTokenHint, "state", STATE.toString()));

            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.of(STATE.toString()),
                            getAuditUserWhenCookieAndIdTokenHint(event, signedIDToken),
                            audience,
                            Optional.of(SUBJECT.getValue()));
        }

        @Test
        void shouldNotTryToDeleteSessionWhenSessionDoesNotExistWhileLogoutRedirectUriIsMissing()
                throws ParseException {
            var idTokenHint = signedIDToken.serialize();

            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);

            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of("id_token_hint", idTokenHint, "state", STATE.toString()));

            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateDefaultLogoutResponse(
                            Optional.of(STATE.toString()),
                            getAuditUserWhenIdTokenHintAndNoCookie(event, signedIDToken),
                            audience,
                            Optional.of(SUBJECT.getValue()));
        }

        @Test
        void
                shouldRedirectToDefaultLogoutUriWithErrorMessageWhenLogoutUriInRequestDoesNotMatchClientRegistry()
                        throws JOSEException, ParseException {
            session =
                    generateSession()
                            .setEmailAddress(EMAIL)
                            .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
            var idTokenHint = signedIDToken.serialize();
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            SignedJWT signedJWT =
                    TokenGeneratorHelper.generateIDToken(
                            "client-id",
                            SUBJECT,
                            "http://localhost-rp",
                            "id-token-client-session-id",
                            ecSigningKey);
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint",
                                    idTokenHint,
                                    "post_logout_redirect_uri",
                                    "http://localhost/invalidlogout",
                                    "state",
                                    STATE.toString()));
            session.getClientSessions().add(CLIENT_SESSION_ID);
            generateSessionFromCookie(session);
            handler.handleRequest(event, context);

            verify(logoutService, times(1)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"),
                            getAuditUserWhenCookieAndIdTokenHint(event, signedIDToken),
                            signedJWT.getJWTClaimsSet().getAudience().stream().findFirst());
            verifyNoInteractions(cloudwatchMetricsService);
        }

        @Test
        void
                shouldNotTryToDeleteSessionWhenSessionDoesNotExistWhileLogoutUriInRequestDoesNotMatchClientRegistry()
                        throws ParseException {
            var idTokenHint = signedIDToken.serialize();
            when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
            when(dynamoClientService.getClient("client-id"))
                    .thenReturn(Optional.of(createClientRegistry()));
            APIGatewayProxyRequestEvent event =
                    generateRequestEvent(
                            Map.of(
                                    "id_token_hint",
                                    idTokenHint,
                                    "post_logout_redirect_uri",
                                    "http://localhost/invalidlogout",
                                    "state",
                                    STATE.toString()));
            handler.handleRequest(event, context);

            verify(logoutService, times(0)).destroySessions(session);
            verify(logoutService)
                    .generateErrorLogoutResponse(
                            Optional.of(STATE.getValue()),
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"),
                            getAuditUserWhenCookieAndIdTokenHint(event, signedIDToken),
                            signedIDToken.getJWTClaimsSet().getAudience().stream().findFirst());
            verifyNoInteractions(cloudwatchMetricsService);
        }
    }

    private uk.gov.di.orchestration.shared.entity.Session generateSession() {
        return new uk.gov.di.orchestration.shared.entity.Session(SESSION_ID)
                .addClientSession(CLIENT_SESSION_ID);
    }

    private void generateSessionFromCookie(uk.gov.di.orchestration.shared.entity.Session session) {
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
    }

    private void setUpClientSession(String clientSessionId, String clientId) {
        session.getClientSessions().add(clientSessionId);
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }

    private TxmaAuditUser getAuditUserWhenCookieAndIdTokenHint(
            APIGatewayProxyRequestEvent event, SignedJWT idToken) throws ParseException {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(event))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(event.getHeaders()))
                .withGovukSigninJourneyId(idToken.getJWTClaimsSet().getStringClaim("sid"))
                .withSessionId(getSessionId(session))
                .withUserId(getInternalCommonSubjectIdentifier(session));
    }

    private TxmaAuditUser getAuditUserWhenIdTokenHintAndNoCookie(
            APIGatewayProxyRequestEvent event, SignedJWT idToken) throws ParseException {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(event))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(event.getHeaders()))
                .withGovukSigninJourneyId(idToken.getJWTClaimsSet().getStringClaim("sid"))
                .withSessionId(null)
                .withUserId(null);
    }

    private TxmaAuditUser getAuditUserWhenCookieAndNoIdTokenHint(
            APIGatewayProxyRequestEvent event) {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(event))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(event.getHeaders()))
                .withGovukSigninJourneyId(
                        extractClientSessionIdFromCookieHeaders(event.getHeaders()).orElse(null))
                .withSessionId(getSessionId(session))
                .withUserId(getInternalCommonSubjectIdentifier(session));
    }

    private TxmaAuditUser getAuditUserWhenNoCookie(APIGatewayProxyRequestEvent event) {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(event))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(event.getHeaders()))
                .withGovukSigninJourneyId(
                        extractClientSessionIdFromCookieHeaders(event.getHeaders()).orElse(null))
                .withSessionId(null)
                .withUserId(null);
    }

    private String getSessionId(uk.gov.di.orchestration.shared.entity.Session session) {
        try {
            return session.getSessionId();
        } catch (NullPointerException e) {
            return null;
        }
    }

    private String getInternalCommonSubjectIdentifier(
            uk.gov.di.orchestration.shared.entity.Session session) {
        try {
            return session.getInternalCommonSubjectIdentifier();
        } catch (NullPointerException e) {
            return null;
        }
    }

    private Optional<String> extractClientSessionIdFromCookieHeaders(Map<String, String> headers) {
        var sessionCookieIds = new CookieHelper().parseSessionCookie(headers);
        return sessionCookieIds.map(CookieHelper.SessionCookieIds::getClientSessionId);
    }
}
