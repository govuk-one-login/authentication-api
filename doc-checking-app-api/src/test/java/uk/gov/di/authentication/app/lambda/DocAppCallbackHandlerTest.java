package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.NoSessionEntity;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.NoSessionException;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NoSessionOrchestrationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private DocAppCallbackHandler handler;
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final DocAppAuthorisationService responseService =
            mock(DocAppAuthorisationService.class);
    private final DocAppCriService tokenService = mock(DocAppCriService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoDocAppService dynamoDocAppService = mock(DynamoDocAppService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private final CookieHelper cookieHelper = mock(CookieHelper.class);

    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";
    private static final URI CRI_URI = URI.create("http://cri/");
    private static final String ENVIRONMENT = "test-environment";
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

    private static final State RP_STATE = new State();

    private final Session session = new Session(SESSION_ID).setEmailAddress(TEST_EMAIL_ADDRESS);

    private final ClientSession clientSession =
            new ClientSession(generateAuthRequest().toParameters(), null, null, null);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(DocAppCallbackHandler.class);

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
                        dynamoDocAppService,
                        cookieHelper,
                        cloudwatchMetricsService,
                        noSessionOrchestrationService);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URL));
        when(configService.getDocAppBackendURI()).thenReturn(CRI_URI);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
        when(configService.getEnvironment()).thenReturn(ENVIRONMENT);
    }

    @Test
    void shouldRedirectToFrontendCallbackForSuccessfulResponse()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
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
        when(tokenService.sendCriDataRequest(any(HTTPRequest.class), any(String.class)))
                .thenReturn(List.of("a-verifiable-credential"));

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        var response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("doc-app-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verify(dynamoDocAppService)
                .addDocAppCredential(
                        PAIRWISE_SUBJECT_ID.getValue(), List.of("a-verifiable-credential"));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of("Environment", ENVIRONMENT, "Successful", Boolean.toString(true)));
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionIsNotFoundInRedis() throws URISyntaxException {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("error").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenNoDocAppSubjectIdIsPresentInClientSession()
            throws URISyntaxException {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        usingValidSession();
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));

        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("error").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToRPWhenAuthnResponseContainsError() {
        usingValidSession();
        usingValidClientSession();

        ErrorObject errorObject =
                new ErrorObject(
                        OAuth2Error.ACCESS_DENIED.getCode(),
                        OAuth2Error.ACCESS_DENIED.getDescription());

        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.of(errorObject));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();

        var response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));

        verifyNoInteractions(tokenService);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        verifyNoInteractions(dynamoDocAppService);
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Successful",
                                Boolean.toString(false),
                                "NoSessionError",
                                Boolean.toString(false),
                                "Error",
                                OAuth2Error.ACCESS_DENIED_CODE));
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenTokenResponseIsNotSuccessful()
            throws URISyntaxException {
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

        var response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("error").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Doc App TokenResponse was not successful: ")));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoDocAppService);
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Successful",
                                Boolean.toString(false),
                                "NoSessionError",
                                Boolean.toString(false),
                                "Error",
                                "UnsuccessfulTokenResponse"));
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenCRIRequestIsNotSuccessful()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
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
        when(tokenService.sendCriDataRequest(any(HTTPRequest.class), any(String.class)))
                .thenThrow(UnsuccessfulCredentialResponseException.class);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        var response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("error").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Doc App sendCriDataRequest was not successful: ")));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoDocAppService);
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Successful",
                                Boolean.toString(false),
                                "NoSessionError",
                                Boolean.toString(false),
                                "Error",
                                "UnsuccessfulCredentialResponse"));
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws NoSessionException {
        usingValidSession();
        usingValidClientSession();
        when(configService.isCustomDocAppClaimEnabled()).thenReturn(true);

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("state", STATE.getValue());
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        when(noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                        queryParameters, true))
                .thenReturn(
                        new NoSessionEntity(
                                CLIENT_SESSION_ID, OAuth2Error.ACCESS_DENIED, clientSession));

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
        verifyNoInteractions(tokenService);
        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        CLIENT_SESSION_ID,
                        AuditService.UNKNOWN,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Successful",
                                Boolean.toString(false),
                                "NoSessionError",
                                Boolean.toString(true),
                                "Error",
                                "access_denied"));
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButCallToNoSessionOrchestrationServiceThrowsException()
                    throws URISyntaxException, NoSessionException {
        usingValidSession();
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("state", STATE.getValue());

        Mockito.doThrow(
                        new NoSessionException(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"))
                .when(noSessionOrchestrationService)
                .generateNoSessionOrchestrationEntity(queryParameters, false);

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("error").build();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false")));

        verifyNoInteractions(tokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppService);
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

    private static AuthenticationRequest generateAuthRequest() {
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

    private void verifyAuditServiceEvent(DocAppAuditableEvent docAppAuditableEvent) {
        verify(auditService)
                .submitAuditEvent(
                        docAppAuditableEvent,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        PAIRWISE_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
    }
}
