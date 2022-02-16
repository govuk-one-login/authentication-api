package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.hasContextData;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final InOrder inOrder = inOrder(auditService);
    private static final String EXPECTED_SESSION_COOKIE_STRING =
            "gs=a-session-id.client-session-id; Max-Age=3600; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final String EXPECTED_PERSISTENT_COOKIE_STRING =
            "di-persistent-session-id=a-persistent-session-id; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final String AWS_REQUEST_ID = "aws-request-id";
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final String SCOPE = "email,openid,profile";
    private static final String RESPONSE_TYPE = "code";
    private Session session;
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final State STATE = new State();

    private AuthorisationHandler handler;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthorisationHandler.class);

    @BeforeEach
    public void setUp() {
        when(configService.getDomainName()).thenReturn("auth.ida.digital.cabinet-office.gov.uk");
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(3600);
        when(configService.getPersistentCookieMaxAge()).thenReturn(34190000);
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(authorizationService.getExistingOrCreateNewPersistentSessionId(any()))
                .thenReturn(PERSISTENT_SESSION_ID);
        when(userContext.getClient()).thenReturn(Optional.of(generateClientRegistry()));
        when(context.getAwsRequestId()).thenReturn(AWS_REQUEST_ID);
        handler =
                new AuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        authorizationService,
                        auditService);
        session = new Session("a-session-id");
        when(sessionService.createSession()).thenReturn(session);
    }

    @AfterEach
    public void afterEach() {
        //        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldRedirectToLoginWhenUserHasNoExistingSession() {
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);

        Map<String, String> requestParams = buildRequestParams(null);
        APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertThat(uri.getQuery(), not(containsString("cookie_consent")));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldRedirectToLoginAndForwardCookieConsentWhenPresent() throws ClientNotFoundException {
        when(authorizationService.isClientCookieConsentShared(eq(new ClientID("test-id"))))
                .thenReturn(true);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);
        when(authorizationService.isValidCookieConsentValue("accept")).thenReturn(true);

        new APIGatewayProxyRequestEvent();
        Map<String, String> requestParams = buildRequestParams(Map.of("cookie_consent", "accept"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertThat(uri.getQuery(), containsString("cookie_consent=accept"));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));
    }

    @Test
    void shouldRedirectToLoginAndNotForwardCookieConsentWhenValueIsInvalid()
            throws ClientNotFoundException {
        when(authorizationService.isClientCookieConsentShared(eq(new ClientID("test-id"))))
                .thenReturn(true);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);
        when(authorizationService.isValidCookieConsentValue("rubbish")).thenReturn(false);

        new APIGatewayProxyRequestEvent();
        Map<String, String> requestParams = buildRequestParams(Map.of("cookie_consent", "rubbish"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertNull(uri.getQuery());
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));
    }

    @Test
    void shouldRedirectToLoginAndForwardGAParameterWhenPresent() throws ClientNotFoundException {
        when(authorizationService.isClientCookieConsentShared(eq(CLIENT_ID))).thenReturn(false);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);

        Map<String, String> requestParams =
                buildRequestParams(
                        Map.of("_ga", "2.172053219.1139384417.1636392870-547301795.1635165988"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertThat(
                uri.getQuery(),
                containsString("_ga=2.172053219.1139384417.1636392870-547301795.1635165988"));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));
    }

    @Test
    void shouldRedirectToLoginWithPromptParamWhenSetToLoginAndExistingSessionIsPresent() {
        withExistingSession(session);
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(userContext.getSession()).thenReturn(session);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);

        Map<String, String> requestParams = buildRequestParams(Map.of("prompt", "login"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
        assertThat(uri.getQuery(), containsString("prompt=login"));

        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));

        verify(sessionService).save(eq(session));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldRedirectToLoginWhenUserNeedsToBeUplifted() {
        session.setCurrentCredentialStrength(CredentialTrustLevel.LOW_LEVEL);
        withExistingSession(session);
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(userContext.getSession()).thenReturn(session);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.of(jsonArrayOf("Cl.Cm"))).toParameters());
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);

        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(buildRequestParams(Map.of("vtr", "Cl"))));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());

        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));

        verify(sessionService).save(eq(session));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldRedirectToLoginWhenIdentityIsPresentInVtr() {
        withExistingSession(session);
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(userContext.getSession()).thenReturn(session);
        when(clientSession.getAuthRequestParams())
                .thenReturn(
                        generateAuthRequest(Optional.of(jsonArrayOf("P2.Cl.Cm"))).toParameters());
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);

        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(buildRequestParams(Map.of("vtr", "P2.Cl.Cm"))));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());

        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));

        verify(sessionService).save(eq(session));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestCannotBeParsed() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id",
                        CLIENT_ID.getValue(),
                        "redirect_uri",
                        REDIRECT_URI,
                        "scope",
                        SCOPE,
                        "invalid_parameter",
                        "nonsense",
                        "state",
                        STATE.getValue()));
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertEquals(
                "https://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Missing+response_type+parameter&state="
                        + STATE.getValue(),
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        AWS_REQUEST_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PERSISTENT_SESSION_ID,
                        pair("description", "Invalid request: Missing response_type parameter"));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestContainsInvalidScope() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile,non-existent-scope",
                        "response_type", "code"));
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        AWS_REQUEST_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PERSISTENT_SESSION_ID,
                        pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
    }

    @Test
    void shouldThrowExceptionWhenNoQueryStringParametersArePresent() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

        RuntimeException expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> makeHandlerRequest(event),
                        "Expected to throw AccessTokenException");

        assertThat(
                expectedException.getMessage(),
                equalTo("No query string parameters are present in the Authentication request"));
    }

    @Test
    void shouldReturnErrorWhenUnrecognisedPromptValue() {
        Map<String, String> requestParams = buildRequestParams(Map.of("prompt", "unrecognised"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        assertThat(response, hasStatus(302));
        assertEquals(
                "https://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Invalid+prompt+parameter%3A+Unknown+prompt+type%3A+unrecognised&state="
                        + STATE.getValue(),
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        AWS_REQUEST_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PERSISTENT_SESSION_ID,
                        pair(
                                "description",
                                "Invalid request: Invalid prompt parameter: Unknown prompt type: unrecognised"));
    }

    private static Stream<Arguments> invalidPromptValues() {
        return Stream.of(
                Arguments.of("login consent", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS),
                Arguments.of("consent", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS),
                Arguments.of("select_account", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS));
    }

    @ParameterizedTest
    @MethodSource("invalidPromptValues")
    void shouldReturnErrorWhenInvalidPromptValuesArePassed(
            String invalidPromptValues, ErrorObject expectedError) {
        Map<String, String> requestParams =
                buildRequestParams(Map.of("prompt", invalidPromptValues));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(expectedError.getCode()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        AWS_REQUEST_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PERSISTENT_SESSION_ID,
                        pair("description", expectedError.getDescription()));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                        AWS_REQUEST_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PERSISTENT_SESSION_ID);

        LogEvent logEvent = logging.events().get(0);

        assertThat(logEvent, hasContextData("persistentSessionId", PERSISTENT_SESSION_ID));
        assertThat(logEvent, hasContextData("awsRequestId", AWS_REQUEST_ID));

        return response;
    }

    private APIGatewayProxyRequestEvent withRequestEvent(Map<String, String> requestParams) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(requestParams);
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
        return event;
    }

    private Map<String, String> buildRequestParams(Map<String, String> extraParams) {
        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("client_id", CLIENT_ID.getValue());
        requestParams.put("redirect_uri", REDIRECT_URI);
        requestParams.put("scope", SCOPE);
        requestParams.put("response_type", RESPONSE_TYPE);
        requestParams.put("state", STATE.getValue());

        if (extraParams != null && !extraParams.isEmpty()) {
            requestParams.putAll(extraParams);
        }
        return requestParams;
    }

    private AuthenticationRequest generateAuthRequest(Optional<String> credentialTrustLevel) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce());
        credentialTrustLevel.ifPresent(t -> builder.customParameter("vtr", t));
        return builder.build();
    }

    private void withExistingSession(Session session) {
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.of(session));
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn(CLIENT_SESSION_ID);
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .setClientID(new ClientID().getValue())
                .setConsentRequired(false)
                .setClientName("test-client")
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("public");
    }
}
