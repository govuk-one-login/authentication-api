package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private DocAppCallbackHandler handler;
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final DocAppAuthorisationService responseService =
            mock(DocAppAuthorisationService.class);
    private final DocAppCriService tokenService = mock(DocAppCriService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoDocAppService dynamoDocAppService = mock(DynamoDocAppService.class);

    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String REQUEST_ID = "a-request-id";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Subject PAIRWISE_SUBJECT_ID = new Subject();
    private static final State STATE = new State();

    private final Session session = new Session(SESSION_ID).setEmailAddress(TEST_EMAIL_ADDRESS);

    private final ClientSession clientSession =
            new ClientSession(generateAuthRequest().toParameters(), null, null);

    @BeforeEach
    void setUp() {
        handler =
                new DocAppCallbackHandler(
                        configService,
                        responseService,
                        tokenService,
                        sessionService,
                        clientSessionService,
                        auditService,
                        dynamoDocAppService);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URL));
        when(configService.isSpotEnabled()).thenReturn(true);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
    }

    @Test
    void shouldRedirectToFrontendCallbackForSuccessfulResponse() throws URISyntaxException {
        usingValidSession();
        usingValidClientSession();
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(tokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(tokenService.sendTokenRequest(tokenRequest)).thenReturn(successfulTokenResponse);
        when(tokenService.sendCriDataRequest(successfulTokenResponse.getTokens().getAccessToken()))
                .thenReturn("a-verifiable-credential");

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        var response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        var expectedRedirectURI =
                new URIBuilder(LOGIN_URL).setPath("doc-checking-app-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verifyNoMoreInteractions(auditService);

        verify(dynamoDocAppService)
                .addDocAppCredential(PAIRWISE_SUBJECT_ID.getValue(), "a-verifiable-credential");
    }

    @Test
    void shouldThrowWhenSessionIsNotFoundInRedis() {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(expectedException.getMessage(), containsString("Session not found"));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowWhenAuthnResponseContainsError() {
        usingValidSession();
        usingValidClientSession();
        ErrorObject errorObject =
                new ErrorObject(
                        "invalid_request_redirect_uri", "redirect_uri param must be provided");
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.of(new ErrorObject(errorObject.getCode())));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        RuntimeException expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(), equalTo("Error in Doc App AuthorisationResponse"));

        verifyNoInteractions(tokenService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowWhenTokenResponseIsNotSuccessful() {
        usingValidSession();
        usingValidClientSession();
        var unsuccessfulTokenResponse = new TokenErrorResponse(new ErrorObject("Error object"));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(tokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(tokenService.sendTokenRequest(tokenRequest)).thenReturn(unsuccessfulTokenResponse);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(),
                containsString("Doc App TokenResponse was not successful"));

        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verifyNoMoreInteractions(auditService);
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(event, context);
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;");
    }

    private void usingValidSession() {
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
        clientSession.setDocAppSubjectId(PAIRWISE_SUBJECT_ID);
    }

    public static AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }
}
