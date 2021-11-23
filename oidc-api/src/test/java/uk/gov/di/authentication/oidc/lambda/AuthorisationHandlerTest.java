package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final InOrder inOrder = inOrder(auditService);
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            mock(StateMachine.class);
    private static final String EXPECTED_SESSION_COOKIE_STRING =
            "gs=a-session-id.client-session-id; Max-Age=3600; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final String EXPECTED_PERSISTENT_COOKIE_STRING =
            "di-persistent-session-id=a-persistent-session-id; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final URI LOGIN_URL = URI.create("https://example.com");

    private AuthorisationHandler handler;

    @BeforeEach
    public void setUp() {
        when(context.getAwsRequestId()).thenReturn("request-id");
        when(configService.getDomainName()).thenReturn("auth.ida.digital.cabinet-office.gov.uk");
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(3600);
        when(configService.getPersistentCookieMaxAge()).thenReturn(34190000);
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(authorizationService.getExistingOrCreateNewPersistentSessionId(any()))
                .thenReturn("a-persistent-session-id");
        when(sessionService.createSession()).thenReturn(new Session("new-session"));
        handler =
                new AuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        authorizationService,
                        auditService,
                        stateMachine);
        when(stateMachine.transition(
                        eq(AUTHENTICATED),
                        eq(USER_HAS_STARTED_A_NEW_JOURNEY),
                        any(UserContext.class)))
                .thenReturn(AUTHENTICATED);
        when(stateMachine.transition(
                        eq(MFA_CODE_NOT_VALID),
                        eq(USER_HAS_STARTED_A_NEW_JOURNEY),
                        any(UserContext.class)))
                .thenReturn(MFA_CODE_NOT_VALID);
        when(stateMachine.transition(
                        eq(AUTHENTICATED),
                        eq(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED),
                        any(UserContext.class)))
                .thenReturn(NEW);
        when(stateMachine.transition(
                        eq(AUTHENTICATION_REQUIRED),
                        eq(USER_HAS_STARTED_A_NEW_JOURNEY),
                        any(UserContext.class)))
                .thenReturn(NEW);
    }

    @AfterEach
    public void afterEach() {
        //        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldSetCookieAndRedirectToLoginOnSuccess() {
        final Session session = new Session("a-session-id");

        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "response_type", "code",
                        "state", "some-state"));
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
    }

    @Test
    void shouldDoLoginAndForwardCookieConsent() throws ClientNotFoundException {
        final Session session = new Session("a-session-id");

        when(authorizationService.isClientCookieConsentShared(eq(new ClientID("test-id"))))
                .thenReturn(true);
        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("cookie_consent", "accept")));
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
    void shouldDoLoginAndForwardGAParameter() throws ClientNotFoundException {
        final Session session = new Session("a-session-id");

        when(authorizationService.isClientCookieConsentShared(eq(new ClientID("test-id"))))
                .thenReturn(false);
        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(
                        withRequestEvent(
                                Map.of(
                                        "_ga",
                                        "2.172053219.1139384417.1636392870-547301795.1635165988")));
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
    void shouldReturn400WhenAuthorisationRequestCannotBeParsed() {
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "invalid_parameter", "nonsense",
                        "state", state.toString()));
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Missing+response_type+parameter&state="
                        + state,
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
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
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.NEW, session.getState());

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    @Test
    void shouldSkipLoginWhenPromptParamAbsentAndLoggedIn() throws URISyntaxException {
        final Session session = new Session("a-session-id");
        session.addClientSession("old-client-session-id");

        whenLoggedIn(session);
        when(authorizationService.buildUserContext(eq(session), any(ClientSession.class)))
                .thenReturn(userContext);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
        URI expectedUri =
                new URIBuilder(LOGIN_URL)
                        .addParameter("interrupt", AUTHENTICATED.toString())
                        .build();

        assertThat(response, hasStatus(302));
        assertEquals(expectedUri, uri);
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATED, session.getState());
        assertThat(session.getClientSessions(), hasItem("client-session-id"));
        assertThat(session.getClientSessions(), hasSize(2));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    @Test
    void shouldReturnErrorWhenPromptParamNoneAndNotLoggedIn() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "none")));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString("error=login_required"));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair("description", OIDCError.LOGIN_REQUIRED.getDescription()));
    }

    @Test
    void shouldSkipLoginWhenPromptParamNoneAndLoggedIn() throws URISyntaxException {
        final Session session = new Session("a-session-id");
        session.addClientSession("old-client-session-id");

        whenLoggedIn(session);
        when(authorizationService.buildUserContext(eq(session), any(ClientSession.class)))
                .thenReturn(userContext);

        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "none")));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        URI expectedUri =
                new URIBuilder(LOGIN_URL)
                        .addParameter("interrupt", AUTHENTICATED.toString())
                        .build();

        assertThat(response, hasStatus(302));
        assertEquals(expectedUri, uri);
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATED, session.getState());
        assertThat(session.getClientSessions(), hasItem("client-session-id"));
        assertThat(session.getClientSessions(), hasSize(2));

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        "a-session-id",
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    @Test
    void shouldDoLoginWhenPromptParamLoginAndNotLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "login")));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());

        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_SESSION_COOKIE_STRING));
        assertTrue(
                response.getMultiValueHeaders()
                        .get(ResponseHeaders.SET_COOKIE)
                        .contains(EXPECTED_PERSISTENT_COOKIE_STRING));

        verify(sessionService).save(eq(session));
        assertEquals(SessionState.NEW, session.getState());

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        "a-session-id",
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    @Test
    void shouldDoLoginWhenPromptParamLoginAndLoggedIn() {
        final Session session = new Session("a-session-id");

        whenLoggedIn(session);
        when(authorizationService.buildUserContext(eq(session), any(ClientSession.class)))
                .thenReturn(userContext);

        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "login")));
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
        assertEquals(SessionState.NEW, session.getState());

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        "a-session-id",
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED));
    }

    @Test
    void shouldReturnErrorWhenUnrecognisedPromptValue() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "unrecognised")));
        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Invalid+prompt+parameter%3A+Unknown+prompt+type%3A+unrecognised&state=some-state",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair(
                                "description",
                                "Invalid request: Invalid prompt parameter: Unknown prompt type: unrecognised"));
    }

    @Test
    void shouldReturnErrorWhenPromptParamWithMultipleValuesNoneAndLogin() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "none login")));
        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Invalid+prompt+parameter%3A+Invalid+prompt%3A+none+login&state=some-state",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair(
                                "description",
                                "Invalid request: Invalid prompt parameter: Invalid prompt: none login"));
    }

    @Test
    void shouldReturnErrorWhenPromptParamWithUnsupportedMultipleValues() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "login consent")));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldReturnErrorWhenPromptParamConsent() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "consent")));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldReturnErrorWhenPromptParamSelectAccount() {
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withRequestEvent(Map.of("prompt", "select_account")));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedInBecauseNoSession() {
        final Session session = new Session("a-session-id");

        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.empty());
        when(sessionService.createSession()).thenReturn(session);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
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
        assertEquals(SessionState.NEW, session.getState());

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        "a-session-id",
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedInBecauseSessionNotAuthenticated() {
        final Session session = new Session("a-session-id");
        whenLoggedIn(session);
        session.setState(SessionState.AUTHENTICATION_REQUIRED);
        when(authorizationService.buildUserContext(eq(session), any(ClientSession.class)))
                .thenReturn(userContext);
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
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
        assertEquals(SessionState.NEW, session.getState());

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_INITIATED,
                        context.getAwsRequestId(),
                        "a-session-id",
                        "test-id",
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        pair("session-action", USER_HAS_STARTED_A_NEW_JOURNEY));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                        "request-id",
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "");

        return response;
    }

    private APIGatewayProxyRequestEvent withRequestEvent() {
        return withRequestEvent(null);
    }

    private APIGatewayProxyRequestEvent withRequestEvent(Map<String, String> extraParams) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("client_id", "test-id");
        requestParams.put("redirect_uri", "http://localhost:8080");
        requestParams.put("scope", "email,openid,profile");
        requestParams.put("response_type", "code");
        requestParams.put("state", "some-state");

        if (extraParams != null && !extraParams.isEmpty()) {
            requestParams.putAll(extraParams);
        }

        event.setQueryStringParameters(requestParams);
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
        return event;
    }

    private void whenLoggedIn(Session session) {
        session.setState(SessionState.AUTHENTICATED);
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.of(session));
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");
    }
}
