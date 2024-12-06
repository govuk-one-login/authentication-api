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
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
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
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
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
    private String idTokenHint;
    private static final Subject INTERNAL_COMMON_SUBJECT_ID = new Subject();
    private static final String EMAIL = "joe.bloggs@test.com";
    private uk.gov.di.orchestration.shared.entity.Session session;
    private OrchSessionItem orchSession;

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
                                        INTERNAL_COMMON_SUBJECT_ID.toString()))));
    }

    @BeforeEach
    void setUp() throws JOSEException {
        handler =
                new LogoutHandler(
                        sessionService,
                        orchSessionService,
                        dynamoClientService,
                        tokenValidationService,
                        logoutService);
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id",
                        INTERNAL_COMMON_SUBJECT_ID,
                        "http://localhost-rp",
                        "id-token-client-session-id",
                        ecSigningKey);
        idTokenHint = signedIDToken.serialize();

        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(logoutService.handleLogout(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new APIGatewayProxyResponseEvent());
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(dynamoClientService.getClient("client-id"))
                .thenReturn(Optional.of(createClientRegistry()));
        when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
        session =
                generateSession()
                        .setEmailAddress(EMAIL)
                        .setInternalCommonSubjectIdentifier(INTERNAL_COMMON_SUBJECT_ID.getValue());
        orchSession =
                new OrchSessionItem()
                        .withSessionId(SESSION_ID)
                        .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID.getValue());
    }

    @Test
    void shouldDestroySessionAndLogoutWhenSessionIsAvailable() {
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", idTokenHint,
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                "state", STATE.toString()));
        setupSessions();
        TxmaAuditUser auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(event))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(event.getHeaders()))
                        .withGovukSigninJourneyId("id-token-client-session-id")
                        .withSessionId(SESSION_ID)
                        .withUserId(INTERNAL_COMMON_SUBJECT_ID.getValue());

        handler.handleRequest(event, context);

        verify(logoutService, times(1))
                .handleLogout(
                        Optional.of(session),
                        Optional.of(orchSession),
                        Optional.empty(),
                        Optional.of(CLIENT_LOGOUT_URI),
                        Optional.of(STATE.toString()),
                        auditUser,
                        Optional.of("client-id"),
                        Optional.of(INTERNAL_COMMON_SUBJECT_ID.getValue()));
    }

    @Test
    void shouldNotDestroySessionAndLogoutWhenSessionIsNotAvailable() {
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", idTokenHint,
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                "state", STATE.toString()));
        TxmaAuditUser auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(event))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(event.getHeaders()))
                        .withGovukSigninJourneyId("id-token-client-session-id")
                        .withSessionId(null)
                        .withUserId(null);

        handler.handleRequest(event, context);

        verify(logoutService, times(1))
                .handleLogout(
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.of(CLIENT_LOGOUT_URI),
                        Optional.of(STATE.toString()),
                        auditUser,
                        Optional.of("client-id"),
                        Optional.of(INTERNAL_COMMON_SUBJECT_ID.getValue()));
    }

    @Test
    void shouldNotThrowWhenTryingToDeleteClientSessionWhichHasExpired() {
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint",
                                signedIDToken.serialize(),
                                "post_logout_redirect_uri",
                                CLIENT_LOGOUT_URI.toString(),
                                "state",
                                STATE.toString()));
        setupSessions();
        session.getClientSessions().add("expired-client-session-id");
        TxmaAuditUser auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(event))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(event.getHeaders()))
                        .withGovukSigninJourneyId("id-token-client-session-id")
                        .withSessionId(SESSION_ID)
                        .withUserId(INTERNAL_COMMON_SUBJECT_ID.getValue());

        handler.handleRequest(event, context);

        verify(logoutService, times(1))
                .handleLogout(
                        Optional.of(session),
                        Optional.of(orchSession),
                        Optional.empty(),
                        Optional.of(CLIENT_LOGOUT_URI),
                        Optional.of(STATE.toString()),
                        auditUser,
                        Optional.of("client-id"),
                        Optional.of(INTERNAL_COMMON_SUBJECT_ID.getValue()));
    }

    private uk.gov.di.orchestration.shared.entity.Session generateSession() {
        return new uk.gov.di.orchestration.shared.entity.Session(SESSION_ID)
                .addClientSession(CLIENT_SESSION_ID);
    }

    private void generateSessionFromCookie(
            uk.gov.di.orchestration.shared.entity.Session session, OrchSessionItem orchSession) {
        when(sessionService.getSessionFromSessionCookie(anyMap())).thenReturn(Optional.of(session));
        when(orchSessionService.getSessionFromSessionCookie(anyMap()))
                .thenReturn(Optional.of(orchSession));
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
        generateSessionFromCookie(session, orchSession);
    }

    private void setUpClientSession(String clientSessionId, String clientId) {
        session.getClientSessions().add(clientSessionId);
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }
}
