package uk.gov.di.authentication.oidc.entity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class LogoutRequestTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private static final State STATE = new State();
    private static final String COOKIE = "Cookie";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private SignedJWT signedIDToken;
    private static final Subject SUBJECT = new Subject();
    private final ClientRegistry clientRegistry = createClientRegistry();
    private String idTokenHint;
    private String rpPairwiseId;
    private OrchSessionItem orchSession;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(LogoutRequest.class);

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
    void setUp() throws JOSEException {
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        "client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
    }

    @BeforeEach
    void sessionExistsSetup() throws ParseException {
        orchSession =
                new OrchSessionItem(SESSION_ID).withInternalCommonSubjectId(SUBJECT.getValue());
        idTokenHint = signedIDToken.serialize();
        rpPairwiseId = signedIDToken.getJWTClaimsSet().getSubject();
    }

    @Test
    void shouldCorrectlyParseACompleteLogoutRequest() {
        when(dynamoClientService.getClient("client-id")).thenReturn(Optional.of(clientRegistry));
        when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);

        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint", idTokenHint,
                                "post_logout_redirect_uri", CLIENT_LOGOUT_URI.toString(),
                                "state", STATE.toString()));
        setupSessions();

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.of(idTokenHint), logoutRequest.idTokenHint());
        assertTrue(logoutRequest.isTokenSignatureValid());
        assertEquals(Optional.empty(), logoutRequest.errorObject());
        assertEquals(Optional.of("client-id"), logoutRequest.clientId());
        assertEquals(Optional.of(rpPairwiseId), logoutRequest.rpPairwiseId());
        assertEquals(Optional.of(CLIENT_LOGOUT_URI), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.of(clientRegistry), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseALogoutRequestWithNoQueryParams() {
        APIGatewayProxyRequestEvent event = generateRequestEvent(null);
        setupSessions();

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(Optional.empty(), logoutRequest.queryStringParameters());
        assertEquals(Optional.empty(), logoutRequest.state());
        assertEquals(Optional.empty(), logoutRequest.idTokenHint());
        assertFalse(logoutRequest.isTokenSignatureValid());
        assertEquals(Optional.empty(), logoutRequest.errorObject());
        assertEquals(Optional.empty(), logoutRequest.clientId());
        assertEquals(Optional.empty(), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.empty(), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseALogoutRequestWithNoSessionCookie() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        when(dynamoClientService.getClient("client-id")).thenReturn(Optional.of(clientRegistry));
        when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint",
                        idTokenHint,
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.empty(), logoutRequest.orchSession());
        assertEquals(Optional.empty(), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.empty(), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.of(idTokenHint), logoutRequest.idTokenHint());
        assertTrue(logoutRequest.isTokenSignatureValid());
        assertEquals(Optional.empty(), logoutRequest.errorObject());
        assertEquals(Optional.of("client-id"), logoutRequest.clientId());
        assertEquals(Optional.of(rpPairwiseId), logoutRequest.rpPairwiseId());
        assertEquals(Optional.of(CLIENT_LOGOUT_URI), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.of(clientRegistry), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseALogoutRequestWithNoTokenHint() {
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "post_logout_redirect_uri",
                                CLIENT_LOGOUT_URI.toString(),
                                "state",
                                STATE.toString()));
        orchSession.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(orchSession);

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.empty(), logoutRequest.idTokenHint());
        assertFalse(logoutRequest.isTokenSignatureValid());
        assertEquals(Optional.empty(), logoutRequest.errorObject());
        assertEquals(Optional.empty(), logoutRequest.clientId());
        assertEquals(Optional.empty(), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.empty(), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseALogoutRequestWhenSignatureIdTokenIsInvalid() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", new Subject(), "http://localhost-rp", ecSigningKey);
        String serializedJwt = signedJWT.serialize();
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint",
                                serializedJwt,
                                "post_logout_redirect_uri",
                                CLIENT_LOGOUT_URI.toString()));
        orchSession.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(orchSession);

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.empty(), logoutRequest.state());
        assertEquals(Optional.of(serializedJwt), logoutRequest.idTokenHint());
        assertFalse(logoutRequest.isTokenSignatureValid());
        assertEquals(
                Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "unable to validate id_token_hint")),
                logoutRequest.errorObject());
        assertEquals(Optional.empty(), logoutRequest.clientId());
        assertEquals(Optional.empty(), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.empty(), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseALogoutRequestWhenClientIsNotFoundInClientRegistry()
            throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateIDToken(
                        "invalid-client-id", SUBJECT, "http://localhost-rp", ecSigningKey);
        String serializedJwt = signedJWT.serialize();
        when(tokenValidationService.isTokenSignatureValid(serializedJwt)).thenReturn(true);
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint",
                                serializedJwt,
                                "post_logout_redirect_uri",
                                CLIENT_LOGOUT_URI.toString(),
                                "state",
                                STATE.toString()));
        orchSession.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(orchSession);

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.of(serializedJwt), logoutRequest.idTokenHint());
        assertTrue(logoutRequest.isTokenSignatureValid());
        assertEquals(
                Optional.of(
                        new ErrorObject(OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found")),
                logoutRequest.errorObject());
        assertEquals(Optional.of("invalid-client-id"), logoutRequest.clientId());
        assertEquals(Optional.of(rpPairwiseId), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.empty(), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseLogoutRequestWhenRedirectUriIsMissing() {
        orchSession.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(orchSession);
        when(dynamoClientService.getClient("client-id")).thenReturn(Optional.of(clientRegistry));

        when(tokenValidationService.isTokenSignatureValid(idTokenHint)).thenReturn(true);

        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of("id_token_hint", idTokenHint, "state", STATE.toString()));

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.of(idTokenHint), logoutRequest.idTokenHint());
        assertTrue(logoutRequest.isTokenSignatureValid());
        assertEquals(Optional.empty(), logoutRequest.errorObject());
        assertEquals(Optional.of("client-id"), logoutRequest.clientId());
        assertEquals(Optional.of(rpPairwiseId), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.of(clientRegistry), logoutRequest.clientRegistry());
    }

    @Test
    void shouldCorrectlyParseLogoutRequestWhenLogoutUriInRequestDoesNotMatchClientRegistry() {
        when(tokenValidationService.isTokenSignatureValid(signedIDToken.serialize()))
                .thenReturn(true);
        when(dynamoClientService.getClient("client-id")).thenReturn(Optional.of(clientRegistry));
        APIGatewayProxyRequestEvent event =
                generateRequestEvent(
                        Map.of(
                                "id_token_hint",
                                signedIDToken.serialize(),
                                "post_logout_redirect_uri",
                                "http://localhost/invalidlogout",
                                "state",
                                STATE.toString()));
        orchSession.getClientSessions().add(CLIENT_SESSION_ID);
        generateSessionFromCookie(orchSession);

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService,
                        tokenValidationService,
                        dynamoClientService,
                        event,
                        orchSessionService);

        assertEquals(Optional.of(orchSession), logoutRequest.orchSession());
        assertEquals(Optional.of(SUBJECT.getValue()), logoutRequest.internalCommonSubjectId());
        assertEquals(Optional.of(SESSION_ID), logoutRequest.sessionId());
        assertEquals(
                Optional.of(event.getQueryStringParameters()),
                logoutRequest.queryStringParameters());
        assertEquals(Optional.of(STATE.getValue()), logoutRequest.state());
        assertEquals(Optional.of(signedIDToken.serialize()), logoutRequest.idTokenHint());
        assertTrue(logoutRequest.isTokenSignatureValid());
        assertEquals(
                Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "client registry does not contain post_logout_redirect_uri")),
                logoutRequest.errorObject());
        assertEquals(Optional.of("client-id"), logoutRequest.clientId());
        assertEquals(Optional.of(rpPairwiseId), logoutRequest.rpPairwiseId());
        assertEquals(Optional.empty(), logoutRequest.postLogoutRedirectUri());
        assertEquals(Optional.of(clientRegistry), logoutRequest.clientRegistry());
    }

    private void generateSessionFromCookie(OrchSessionItem orchSession) {
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
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

    private static String buildCookieString() {
        return format(
                "gs=%s.%s; %s=%s; Max-Age=%d; %s",
                SESSION_ID,
                LogoutRequestTest.CLIENT_SESSION_ID,
                CookieHelper.PERSISTENT_COOKIE_NAME,
                PERSISTENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;");
    }

    private static APIGatewayProxyRequestEvent generateRequestEvent(
            Map<String, String> queryStringParameters) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        if (queryStringParameters != null) {
            event.setQueryStringParameters(queryStringParameters);
        }
        return event;
    }

    private void setupSessions() {
        setUpClientSession("client-session-id-2", "client-id-2");
        setUpClientSession("client-session-id-3", "client-id-3");
        generateSessionFromCookie(orchSession);
    }

    private void setUpClientSession(String clientSessionId, String clientId) {
        orchSession.getClientSessions().add(clientSessionId);
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }
}
