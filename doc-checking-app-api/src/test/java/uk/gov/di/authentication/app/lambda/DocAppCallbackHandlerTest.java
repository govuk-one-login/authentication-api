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
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.DocAppCriAPI;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withThrownMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private DocAppCallbackHandler handler;
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final DocAppAuthorisationService responseService =
            mock(DocAppAuthorisationService.class);
    private final DocAppCriService tokenService = mock(DocAppCriService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoDocAppCriService dynamoDocAppCriService =
            mock(DynamoDocAppCriService.class);
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private static final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final DocAppCriAPI docAppCriApi = mock(DocAppCriAPI.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);

    private static final URI EXPECTED_ERROR_REDIRECT_URI = URI.create("https://example.com/error");

    private static final URI DOC_APP_CRI_V2_URI = URI.create("https://base-url.com/userinfo/v2");
    private static final URI CRI_URI = URI.create("http://cri/");
    private static final String ENVIRONMENT = "test-environment";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String REQUEST_ID = "a-request-id";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Subject PAIRWISE_SUBJECT_ID = new Subject();
    public static final TxmaAuditUser BASE_AUDIT_USER =
            TxmaAuditUser.user()
                    .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                    .withSessionId(SESSION_ID)
                    .withUserId(PAIRWISE_SUBJECT_ID.getValue());
    private static final State STATE = new State();

    private static final State RP_STATE = new State();
    private static final Nonce NONCE = new Nonce();

    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID)
                    .withAccountState(OrchSessionItem.AccountState.EXISTING_DOC_APP_JOURNEY);

    private final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem(
                    CLIENT_SESSION_ID,
                    generateAuthRequest().toParameters(),
                    null,
                    emptyList(),
                    null);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(DocAppCallbackHandler.class);

    @RegisterExtension
    private final CaptureLoggingExtension redirectLogging =
            new CaptureLoggingExtension(RedirectService.class);

    @BeforeEach
    void setUp() {
        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()), eq(CLIENT_SESSION_ID), eq(null), eq(null)))
                .thenReturn(AUTH_CODE);

        handler =
                new DocAppCallbackHandler(
                        configService,
                        responseService,
                        tokenService,
                        orchClientSessionService,
                        auditService,
                        dynamoDocAppCriService,
                        orchAuthCodeService,
                        cloudwatchMetricsService,
                        crossBrowserOrchestrationService,
                        authFrontend,
                        docAppCriApi,
                        orchSessionService);
        when(authFrontend.errorURI()).thenReturn(EXPECTED_ERROR_REDIRECT_URI);
        when(docAppCriApi.criDataURI()).thenReturn(DOC_APP_CRI_V2_URI);
        when(configService.getDocAppBackendURI()).thenReturn(CRI_URI);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(configService.getEnvironment()).thenReturn(ENVIRONMENT);
    }

    @Test
    void shouldRedirectToRPForSuccessfulResponse() throws UnsuccessfulCredentialResponseException {
        usingValidClientSession();
        usingValidOrchSession();
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
        var authenticationResponse =
                new AuthenticationSuccessResponse(
                        REDIRECT_URI, AUTH_CODE, null, null, RP_STATE, null, null);
        var expectedRedirectURI = authenticationResponse.toURI();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED);
        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.AUTH_CODE_ISSUED,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER.withIpAddress("123.123.123.123"),
                        pair("internalSubjectId", AuditService.UNKNOWN),
                        pair("isNewAccount", orchSession.getIsNewAccount()),
                        pair("rpPairwiseId", AuditService.UNKNOWN),
                        pair("authCode", AUTH_CODE),
                        pair("nonce", NONCE.getValue()));

        verifyNoMoreInteractions(auditService);
        verify(dynamoDocAppCriService)
                .addDocAppCredential(
                        PAIRWISE_SUBJECT_ID.getValue(), List.of("a-verifiable-credential"));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "DocAppCallback",
                        Map.of("Environment", ENVIRONMENT, "Successful", Boolean.toString(true)));

        assertAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionIsNotFoundInRedis() {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
        verifyNoInteractions(cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenNoOrchSession() {
        usingValidClientSession();
        withNoOrchSession();
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
        verifyNoInteractions(cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenNoDocAppSubjectIdIsPresentInClientSession() {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSession));

        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
        verifyNoInteractions(cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToRPWhenAuthnResponseContainsError() {
        usingValidClientSession();
        usingValidOrchSession();

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
        verifyNoInteractions(dynamoDocAppCriService);
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

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenTokenResponseIsNotSuccessful() {
        usingValidClientSession();
        usingValidOrchSession();
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
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));
        assertThat(
                redirectLogging.events(),
                hasItem(withThrownMessageContaining("Doc App TokenResponse was not successful: ")));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
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

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenCRIRequestIsNotSuccessful()
            throws UnsuccessfulCredentialResponseException {
        usingValidClientSession();
        usingValidOrchSession();
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
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));
        assertThat(
                redirectLogging.events(),
                hasItem(
                        withThrownMessageContaining(
                                "Doc App sendCriDataRequest was not successful: ")));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
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

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws NoSessionException {
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("state", STATE.getValue());
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        when(crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(queryParameters))
                .thenReturn(
                        new CrossBrowserEntity(
                                CLIENT_SESSION_ID, OAuth2Error.ACCESS_DENIED, orchClientSession));

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
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withUserId(PAIRWISE_SUBJECT_ID.getValue()));
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

        assertAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButCallToNoSessionOrchestrationServiceThrowsException()
                    throws NoSessionException {
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("state", STATE.getValue());

        Mockito.doThrow(
                        new NoSessionException(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"))
                .when(crossBrowserOrchestrationService)
                .generateNoSessionOrchestrationEntity(queryParameters);

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(EXPECTED_ERROR_REDIRECT_URI.toString()));
        assertThat(
                redirectLogging.events(),
                hasItem(
                        withThrownMessageContaining(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false")));

        verifyNoInteractions(tokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);

        assertAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateAuthenticationErrorResponseWhenCRIRequestReturns404()
            throws UnsuccessfulCredentialResponseException {
        usingValidClientSession();
        usingValidOrchSession();
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
                .thenThrow(
                        new UnsuccessfulCredentialResponseException(
                                "Received a 404 response from CRI data endpoint", 404));

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        var response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));

        assertThat(
                response.getHeaders().get("Location"),
                containsString("test-uri?error=access_denied&error_description=Not+found&state="));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Error in Doc App AuthorisationResponse")));

        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditServiceEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoDocAppCriService);
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
                                "access_denied"));

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(
                event.withRequestContext(contextWithSourceIp("123.123.123.123")), context);
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;");
    }

    private void usingValidOrchSession() {
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));
    }

    private void withNoOrchSession() {
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.empty());
    }

    private void usingValidClientSession() {
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSession));
        orchClientSession.setDocAppSubjectId(PAIRWISE_SUBJECT_ID.getValue());
    }

    private static AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(NONCE)
                .build();
    }

    private void verifyAuditServiceEvent(DocAppAuditableEvent docAppAuditableEvent) {
        verify(auditService)
                .submitAuditEvent(docAppAuditableEvent, CLIENT_ID.getValue(), BASE_AUDIT_USER);
    }

    private void assertAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(1))
                .generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()), eq(CLIENT_SESSION_ID), eq(null), eq(null));
    }

    private void assertNoAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(0))
                .generateAndSaveAuthorisationCode(any(), any(), any(), any());
    }
}
