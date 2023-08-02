package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.oidc.services.AuthenticationTokenService;
import uk.gov.di.authentication.oidc.services.AuthenticationUserInfoStorageService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationCallbackHandlerTest {
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private final AuthenticationAuthorizationService authorizationService =
            mock(AuthenticationAuthorizationService.class);
    private final AuthenticationTokenService tokenService = mock(AuthenticationTokenService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthenticationUserInfoStorageService userInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private static final CookieHelper cookieHelper = mock(CookieHelper.class);
    private final ClientService clientService = mock(ClientService.class);
    private static final String TEST_FRONTEND_BASE_URL = "test.orchestration.frontend.url";
    private static final String TEST_AUTH_BACKEND_BASE_URL = "https://test.auth.backend.url";
    private static final String TEST_AUTH_USERINFO_PATH = "/test-userinfo";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final String SESSION_ID = "a-session-id";
    private static final Session session =
            new Session(SESSION_ID).setEmailAddress(TEST_EMAIL_ADDRESS);
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Subject PAIRWISE_SUBJECT_ID = new Subject();
    private static final URI REDIRECT_URI = URI.create("https://test.rp.redirect.uri");
    private static final State RP_STATE = new State();
    private static final ClientSession clientSession =
            new ClientSession(
                    generateRPAuthRequestForClientSession().toParameters(),
                    null,
                    new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                    "test-name");
    private static final String COOKIE_HEADER_NAME = "Cookie";
    private static final AuthorizationCode AUTH_CODE_ORCH_TO_AUTH = new AuthorizationCode();
    private static final AuthorizationCode AUTH_CODE_RP_TO_ORCH = new AuthorizationCode();
    private static final State STATE = new State();
    private static final TokenResponse SUCCESSFUL_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
    private static final TokenResponse UNSUCCESSFUL_TOKEN_RESPONSE = mock(TokenResponse.class);
    private static final String TEST_ERROR_MESSAGE = "test-error-message";
    private static final UserInfo USER_INFO = mock(UserInfo.class);
    private AuthenticationCallbackHandler handler;

    @BeforeAll
    static void init() {
        when(configurationService.getEnvironment()).thenReturn("test-env");
        when(configurationService.getLoginURI()).thenReturn(URI.create(TEST_FRONTEND_BASE_URL));
        when(configurationService.getAuthenticationBackendURI())
                .thenReturn(URI.create(TEST_AUTH_BACKEND_BASE_URL));
        when(configurationService.getAuthenticationUserInfoEndpoint())
                .thenReturn(TEST_AUTH_USERINFO_PATH);
        when(authorisationCodeService.generateAuthorisationCode(
                        CLIENT_SESSION_ID, TEST_EMAIL_ADDRESS, clientSession))
                .thenReturn(AUTH_CODE_RP_TO_ORCH);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
        when(UNSUCCESSFUL_TOKEN_RESPONSE.indicatesSuccess()).thenReturn(false);
        when(UNSUCCESSFUL_TOKEN_RESPONSE.toErrorResponse())
                .thenReturn(new TokenErrorResponse(new ErrorObject("1", TEST_ERROR_MESSAGE)));
        when(USER_INFO.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(USER_INFO.getSubject()).thenReturn(PAIRWISE_SUBJECT_ID);
        when(USER_INFO.getClaim("new_account")).thenReturn("true");
    }

    @BeforeEach
    void setUp() {
        handler =
                new AuthenticationCallbackHandler(
                        configurationService,
                        authorizationService,
                        tokenService,
                        sessionService,
                        clientSessionService,
                        auditService,
                        userInfoStorageService,
                        cookieHelper,
                        cloudwatchMetricsService,
                        authorisationCodeService,
                        clientService);
    }

    @Test
    void shouldRedirectToRpRedirectUriWithCodeAndStateOnSuccessfulTokenResponse()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        String redirectLocation = response.getHeaders().get("Location");
        assertThat(
                redirectLocation,
                equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED),
                auditService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionCookieNotFound() {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Collections.emptyMap());

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_BASE_URL + "/error"));

        verifyNoInteractions(
                tokenService, auditService, userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToRpWithErrorWhenRequestIsInvalid() {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE_HEADER_NAME, buildCookieString()));
        when(authorizationService.validateRequest(any(), any()))
                .thenReturn(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE, TEST_ERROR_MESSAGE)));

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        String locationHeaderRedirect = response.getHeaders().get("Location");
        assertThat(locationHeaderRedirect, containsString(REDIRECT_URI.toString()));
        assertThat(locationHeaderRedirect, containsString(TEST_ERROR_MESSAGE));
        assertThat(locationHeaderRedirect, containsString("&state=" + RP_STATE));

        verifyAuditEvents(
                List.of(OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED),
                auditService);

        verifyNoInteractions(tokenService, userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageIfTokenRequestIsUnsuccessful() {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(UNSUCCESSFUL_TOKEN_RESPONSE);

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_BASE_URL + "/error"));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED),
                auditService);
        verifyNoInteractions(userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageIfUserInfoRequestIsUnsuccessful()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                .thenThrow(new UnsuccessfulCredentialResponseException(TEST_ERROR_MESSAGE));

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_BASE_URL + "/error"));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED),
                auditService);
        verifyNoInteractions(userInfoStorageService, cloudwatchMetricsService);
    }

    private static void setValidHeadersAndQueryParameters(APIGatewayProxyRequestEvent event) {
        event.setHeaders(Map.of(COOKIE_HEADER_NAME, buildCookieString()));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE_ORCH_TO_AUTH.getValue());
        responseHeaders.put("state", STATE.getValue());
        event.setQueryStringParameters(responseHeaders);
    }

    private void usingValidSession() {
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private static AuthenticationRequest generateRPAuthRequestForClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .build();
    }

    private static String buildCookieString() {
        return format(
                        "%s=%s.%s; Max-Age=%d; %s",
                        "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;")
                + format(
                        "%s=%s; Max-Age=%d; %s",
                        "di-persistent-session-id",
                        PERSISTENT_SESSION_ID,
                        3600,
                        "Secure; HttpOnly;");
    }

    private static void verifyAuditEvents(
            List<OrchestrationAuditableEvent> auditEvents, AuditService auditService) {
        for (OrchestrationAuditableEvent event : auditEvents) {
            verify(auditService)
                    .submitAuditEvent(
                            eq(event),
                            eq(CLIENT_SESSION_ID),
                            eq(SESSION_ID),
                            eq(CLIENT_ID.getValue()),
                            any(),
                            any(),
                            any(),
                            any(),
                            any());
        }
    }
}
