package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.domain.OidcAuditableEvent;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ResponseHeaders;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.services.AuthorizationService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final AuditService auditService = mock(AuditService.class);

    private static final String EXPECTED_COOKIE_STRING =
            "gs=a-session-id.client-session-id; Max-Age=1800; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";

    final String domainName = "auth.ida.digital.cabinet-office.gov.uk";

    private AuthorisationHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new AuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        authorizationService,
                        auditService);
    }

    @AfterEach
    public void afterEach() {
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldSetCookieAndRedirectToLoginOnSuccess() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(configService.getDomainName()).thenReturn(domainName);
        when(sessionService.createSession()).thenReturn(session);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(1800);
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
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
        final String expectedCookieString =
                "gs=a-session-id.client-session-id; Max-Age=1800; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertEquals(expectedCookieString, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestCannotBeParsed() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "invalid_parameter", "nonsense",
                        "state", state.toString()));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Missing+response_type+parameter&state="
                        + state,
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                "Invalid request: Missing response_type parameter"));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestContainsInvalidData() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile,non-existent-scope",
                        "response_type", "code"));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                OAuth2Error.INVALID_SCOPE.getDescription()));
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(sessionService.createSession()).thenReturn(session);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(1800);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");
        when(configService.getDomainName()).thenReturn(domainName);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.NEW, session.getState());
    }

    @Test
    void shouldSkipLoginWhenPromptParamAbsentAndLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final URI authCodeUri = URI.create("/auth-code");
        final Session session = new Session("a-session-id");
        session.addClientSession("old-client-session-id");

        whenLoggedIn(session, loginUrl);
        when(configService.getAuthCodeURI()).thenReturn(authCodeUri);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(authCodeUri, uri);
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATED, session.getState());
        assertThat(session.getClientSessions(), hasItem("client-session-id"));
        assertThat(session.getClientSessions(), hasSize(2));
    }

    @Test
    void shouldReturnErrorWhenPromptParamNoneAndNotLoggedIn() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withPromptRequestEvent("none"));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString("error=login_required"));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                OIDCError.LOGIN_REQUIRED.getDescription()));
    }

    @Test
    void shouldSkipLoginWhenPromptParamNoneAndLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final URI authCodeUri = URI.create("/auth-code");

        final Session session = new Session("a-session-id");
        session.addClientSession("old-client-session-id");

        whenLoggedIn(session, loginUrl);
        when(configService.getAuthCodeURI()).thenReturn(authCodeUri);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withPromptRequestEvent("none"));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(authCodeUri, uri);
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATED, session.getState());
        assertThat(session.getClientSessions(), hasItem("client-session-id"));
        assertThat(session.getClientSessions(), hasSize(2));
    }

    @Test
    void shouldDoLoginWhenPromptParamLoginAndNotLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(sessionService.createSession()).thenReturn(session);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(1800);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");
        when(configService.getDomainName()).thenReturn(domainName);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withPromptRequestEvent("login"));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());

        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));

        verify(sessionService).save(eq(session));
        assertEquals(SessionState.NEW, session.getState());
    }

    @Test
    void shouldDoLoginWhenPromptParamLoginAndLoggedIn() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        whenLoggedIn(session, loginUrl);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withPromptRequestEvent("login"));
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATION_REQUIRED, session.getState());
    }

    @Test
    void shouldReturnErrorWhenUnrecognisedPromptValue() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withPromptRequestEvent("unrecognised"));
        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Invalid+prompt+parameter%3A+Unknown+prompt+type%3A+unrecognised&state=some-state",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                "Invalid request: Invalid prompt parameter: Unknown prompt type: unrecognised"));
    }

    @Test
    void shouldReturnErrorWhenPromptParamWithMultipleValuesNoneAndLogin() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withPromptRequestEvent("none login"));
        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_request&error_description=Invalid+request%3A+Invalid+prompt+parameter%3A+Invalid+prompt%3A+none+login&state=some-state",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                "Invalid request: Invalid prompt parameter: Invalid prompt: none login"));
    }

    @Test
    void shouldReturnErrorWhenPromptParamWithUnsupportedMultipleValues() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withPromptRequestEvent("login consent"));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldReturnErrorWhenPromptParamConsent() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withPromptRequestEvent("consent"));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldReturnErrorWhenPromptParamSelectAccount() {
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent response =
                makeHandlerRequest(withPromptRequestEvent("select_account"));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE));


        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedInBecauseNoSession() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.empty());
        when(sessionService.createSession()).thenReturn(session);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(1800);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");
        when(configService.getDomainName()).thenReturn(domainName);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.NEW, session.getState());
    }

    @Test
    void shouldDoLoginWhenPromptParamAbsentAndNotLoggedInBecauseSessionNotAuthenticated() {
        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        whenLoggedIn(session, loginUrl);
        session.setState(SessionState.AUTHENTICATION_REQUIRED);

        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent());
        URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());
        assertEquals(EXPECTED_COOKIE_STRING, response.getHeaders().get("Set-Cookie"));
        verify(sessionService).save(eq(session));
        assertEquals(SessionState.AUTHENTICATION_REQUIRED, session.getState());
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService).submitAuditEvent(OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED);

        return response;
    }

    private APIGatewayProxyRequestEvent withPromptRequestEvent(String prompt) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "response_type", "code",
                        "state", "some-state",
                        "prompt", prompt));
        return event;
    }

    private APIGatewayProxyRequestEvent withRequestEvent() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "response_type", "code",
                        "state", "some-state"));
        return event;
    }

    private void whenLoggedIn(Session session, URI loginUrl) {
        session.setState(SessionState.AUTHENTICATED);
        when(authorizationService.validateAuthRequest(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.of(session));
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(1800);
        when(clientSessionService.generateClientSession(any(ClientSession.class)))
                .thenReturn("client-session-id");
        when(configService.getDomainName()).thenReturn(domainName);
    }

    private String getHeaderValueByParamName(
            APIGatewayProxyResponseEvent response, String paramName) {
        return response.getHeaders().get(paramName);
    }
}
