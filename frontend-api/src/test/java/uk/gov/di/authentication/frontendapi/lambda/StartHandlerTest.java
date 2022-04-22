package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartHandlerTest {

    public static final String TEST_CLIENT_ID = "test_client_id";
    public static final String TEST_CLIENT_NAME = "test_client_name";
    public static final String CLIENT_SESSION_ID_HEADER = "Client-Session-Id";
    public static final String SESSION_ID_HEADER = "Session-Id";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String SESSION_ID = "some-session-id";
    public static final String PERSISTENT_ID = "some-persistent-id-value";
    public static final URI REDIRECT_URL = URI.create("https://localhost/redirect");

    private StartHandler handler;
    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final StartService startService = mock(StartService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final Session session = new Session(SESSION_ID);
    private final ClientSession clientSession = getClientSession();

    @BeforeEach
    void beforeEach() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(new Session("session-id")));
        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(clientRegistry.getClientID()).thenReturn(TEST_CLIENT_ID);
        handler =
                new StartHandler(clientSessionService, sessionService, auditService, startService);
    }

    private static Stream<Arguments> cookieConsentGaTrackingIdValues() {
        return Stream.of(
                Arguments.of(null, "some-ga-tracking-id"),
                Arguments.of("some-cookie-consent-value", null),
                Arguments.of(null, null),
                Arguments.of("some-cookie-consent-value", "some-ga-tracking-id"));
    }

    @ParameterizedTest
    @MethodSource("cookieConsentGaTrackingIdValues")
    void shouldReturn200WithStartResponse(String cookieConsentValue, String gaTrackingId)
            throws JsonProcessingException, ParseException {
        var userStartInfo = getUserStartInfo(cookieConsentValue, gaTrackingId);
        when(startService.buildUserContext(session, clientSession)).thenReturn(userContext);
        when(startService.buildClientStartInfo(userContext)).thenReturn(getClientStartInfo());
        when(startService.getGATrackingId(anyMap())).thenReturn(gaTrackingId);
        when(startService.getCookieConsentValue(anyMap(), anyString()))
                .thenReturn(cookieConsentValue);
        when(startService.buildUserStartInfo(userContext, cookieConsentValue, gaTrackingId))
                .thenReturn(userStartInfo);
        usingValidClientSession();
        usingValidSession();

        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        StartResponse response =
                new ObjectMapper().readValue(result.getBody(), StartResponse.class);

        assertThat(
                response.getClient().getClientName(),
                equalTo(getClientStartInfo().getClientName()));
        assertThat(response.getClient().getScopes(), equalTo(getClientStartInfo().getScopes()));
        assertThat(
                response.getClient().getServiceType(),
                equalTo(getClientStartInfo().getServiceType()));
        assertThat(
                response.getClient().getCookieConsentShared(),
                equalTo(getClientStartInfo().getCookieConsentShared()));
        assertThat(response.getClient().getRedirectUri(), equalTo(REDIRECT_URL));
        assertThat(
                response.getUser().isConsentRequired(), equalTo(userStartInfo.isConsentRequired()));
        assertThat(
                response.getUser().isIdentityRequired(),
                equalTo(userStartInfo.isIdentityRequired()));
        assertThat(
                response.getUser().isUpliftRequired(), equalTo(userStartInfo.isUpliftRequired()));
        assertThat(response.getUser().getCookieConsent(), equalTo(cookieConsentValue));
        assertThat(response.getUser().getGaCrossDomainTrackingId(), equalTo(gaTrackingId));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.START_INFO_FOUND,
                        "aws-session-id",
                        SESSION_ID,
                        TEST_CLIENT_ID,
                        auditService.UNKNOWN,
                        auditService.UNKNOWN,
                        "123.123.123.123",
                        PERSISTENT_ID,
                        AuditService.UNKNOWN);
    }

    @Test
    void shouldReturn400WhenClientSessionIsNotFound() throws JsonProcessingException {
        usingInvalidClientSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1018);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenSessionIsNotFound() throws JsonProcessingException {
        usingValidClientSession();
        usingInvalidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        event.setHeaders(headers);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenBuildClientStartInfoThrowsException()
            throws ParseException, JsonProcessingException {
        when(startService.buildUserContext(session, clientSession)).thenReturn(userContext);
        when(startService.buildClientStartInfo(userContext))
                .thenThrow(new ParseException("Unable to parse authentication request"));
        usingValidClientSession();
        usingValidSession();

        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1038);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
    }

    private void usingInvalidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingInvalidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap())).thenReturn(Optional.empty());
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(TEST_CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();
        return new ClientSession(authRequest.toParameters(), null, mock(VectorOfTrust.class));
    }

    private ClientStartInfo getClientStartInfo() {
        Scope scope = new Scope(OIDCScopeValue.OPENID.getValue());

        return new ClientStartInfo(
                TEST_CLIENT_NAME, scope.toStringList(), "MANDATORY", false, REDIRECT_URL);
    }

    private UserStartInfo getUserStartInfo(String cookieConsent, String gaCrossDomainTrackingId) {
        return new UserStartInfo(
                true, false, false, true, cookieConsent, gaCrossDomainTrackingId, false);
    }
}
