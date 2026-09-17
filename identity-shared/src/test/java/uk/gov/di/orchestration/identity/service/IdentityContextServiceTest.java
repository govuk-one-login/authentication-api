package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.CrossBrowserStateMismatchException;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityContextServiceTest {
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final AuthenticationUserInfoStorageService authUserInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final State RP_STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-client-id");
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            "urn:fdc:gov.uk:2022:0VzHWj9aaJpyHXJX8B5QJ-UOUibweHmkSg1GjF6w9yM";
    private static final String RP_PAIRWISE_SUBJECT =
            "urn:fdc:gov.uk:2022:_WJvfEzqmWo6vnDwSqgMPTC-aK8n_fkgZsNF-a4OxxU";
    private static final UserInfo AUTH_USER_INFO = generateAuthUserInfo();

    private final OrchSessionItem orchSession =
            new OrchSessionItem("test-session-id")
                    .withInternalCommonSubjectId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);
    private final AuthenticationRequest authRequest = generateAuthRequest(new OIDCClaimsRequest());
    private final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem(
                            CLIENT_SESSION_ID,
                            authRequest.toParameters(),
                            null,
                            List.of(),
                            "test-client-name")
                    .withRpPairwiseId(RP_PAIRWISE_SUBJECT);
    private final ClientRegistry client =
            new ClientRegistry()
                    .withClientID(CLIENT_ID.getValue())
                    .withClientName("test-client")
                    .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                    .withSectorIdentifierUri("https://test.com")
                    .withSubjectType("pairwise");

    private IdentityContextService service;

    @BeforeEach
    void setup() {
        service =
                new IdentityContextService(
                        crossBrowserOrchestrationService,
                        orchSessionService,
                        orchClientSessionService,
                        dynamoClientService,
                        authUserInfoStorageService);
    }

    @Test
    void
            shouldThrowCrossBrowserNoSessionExceptionWhenNoSessionCookiesAreSetAndSessionFoundUsingState()
                    throws Exception {
        var request = createRequestEvent();
        request.setHeaders(Map.of(COOKIE, ""));
        mockCrossBrowserReturningNoSessionEntity(request);

        assertThrows(CrossBrowserNoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowNoSessionExceptionWhenNoSessionCookiesAreSetAndSessionNotFoundUsingState()
            throws Exception {
        var request = createRequestEvent();
        request.setHeaders(Map.of(COOKIE, ""));
        mockNoSessionFoundFromState(request);

        assertThrows(NoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowNoSessionExceptionWhenNoSessionFoundWithSessionId() {
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.empty());
        var request = createRequestEvent();

        assertThrows(NoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowNoSessionExceptionWhenNoClientSessionFoundWithClientSessionId() {
        usingValidSession();
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
        var request = createRequestEvent();

        assertThrows(NoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowNoSessionExceptionWhenStateParamFieldIsNotPresent() throws Exception {
        usingValidSession();
        usingValidClientSession();
        var request = createRequestEvent();
        when(crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                        request.getQueryStringParameters(), CLIENT_SESSION_ID))
                .thenThrow(new NoSessionException("test"));

        assertThrows(NoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void
            shouldThrowCrossBrowserStateMismatchExceptionWhenStateInParamsDoesNotMatchStateFromClientSession()
                    throws Exception {
        usingValidSession();
        usingValidClientSession();
        var request = createRequestEvent();
        mockStateMismatch(request);

        assertThrows(CrossBrowserStateMismatchException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowParseExceptionWhenClientSessionHasInvalidAuthRequestParams() {
        usingValidSession();
        usingClientSession(orchClientSession.withAuthRequestParams(Map.of()));
        var request = createRequestEvent();

        assertThrows(ParseException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowIdentityCallbackExceptionWhenClientDoesNotExistWithClientId() {
        usingValidSession();
        usingValidClientSession();
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());
        var request = createRequestEvent();

        assertThrows(IdentityCallbackException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowIdentityCallbackExceptionWhenAuthUserInfoIsNotFound() throws Exception {
        usingValidSession();
        usingValidClientSession();
        usingValidClient();
        when(authUserInfoStorageService.getAuthenticationUserInfo(
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER, CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());

        var request = createRequestEvent();
        assertThrows(IdentityCallbackException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldReturnIdentityContext() throws Exception {
        usingValidSession();
        usingValidClientSession();
        usingValidClient();
        usingValidAuthUserInfo();

        var request = createRequestEvent();
        var result = service.buildContext(request);

        assertThat(result.orchSessionItem(), equalTo(orchSession));
        assertThat(result.orchClientSessionItem(), equalTo(orchClientSession));
        assertThat(result.clientRegistry(), equalTo(client));
        assertThat(result.authUserInfo(), equalTo(AUTH_USER_INFO));
        assertThat(result.authRequest().toParameters(), equalTo(authRequest.toParameters()));
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        return createRequestEvent(Map.of());
    }

    private APIGatewayProxyRequestEvent createRequestEvent(Map<String, String> extraParams) {
        Map<String, String> responseParams = new HashMap<>();
        responseParams.put("code", AUTH_CODE.getValue());
        responseParams.put("state", STATE.getValue());
        responseParams.putAll(extraParams);
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseParams);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s di-persistent-session-id=%s; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                "gs",
                SESSION_ID,
                CLIENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;",
                PERSISTENT_SESSION_ID);
    }

    public static AuthenticationRequest generateAuthRequest(OIDCClaimsRequest oidcClaimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .claims(oidcClaimsRequest)
                .responseMode(ResponseMode.QUERY)
                .build();
    }

    private static UserInfo generateAuthUserInfo() {
        return new UserInfo(
                new JSONObject(
                        Map.of(
                                "sub",
                                TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER,
                                "client_session_id",
                                CLIENT_SESSION_ID,
                                "email",
                                "test-email-address",
                                "phone_number",
                                "012345678902",
                                "salt",
                                "TW1jNDhpbUV1TzVra1ZXN050WFZ0eDVoMG1iQ1RmWHNxWGRXdmJSTXpkdz0=",
                                "local_account_id",
                                new Subject().getValue())));
    }

    private void usingValidSession() {
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));
    }

    private void usingValidClientSession() {
        usingClientSession(orchClientSession);
    }

    private void usingClientSession(OrchClientSessionItem clientSession) {
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private void usingValidClient() {
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.of(client));
    }

    private void usingValidAuthUserInfo() throws ParseException {
        when(authUserInfoStorageService.getAuthenticationUserInfo(
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER, CLIENT_SESSION_ID))
                .thenReturn(Optional.of(AUTH_USER_INFO));
    }

    private void mockCrossBrowserReturningNoSessionEntity(APIGatewayProxyRequestEvent request)
            throws Exception {
        var noSessionCrossBrowserEntity =
                new CrossBrowserEntity(
                        "test-csid",
                        new ErrorObject("test-error", "Test Description"),
                        new OrchClientSessionItem("test-csid"));
        when(crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                        request.getQueryStringParameters()))
                .thenReturn(noSessionCrossBrowserEntity);
    }

    private void mockNoSessionFoundFromState(APIGatewayProxyRequestEvent request) throws Exception {
        when(crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                        request.getQueryStringParameters()))
                .thenThrow(new NoSessionException("test"));
    }

    private void mockStateMismatch(APIGatewayProxyRequestEvent request) throws Exception {
        var crossBrowserEntity =
                new CrossBrowserEntity(
                        "test-csid-2",
                        new ErrorObject("test-error"),
                        new OrchClientSessionItem("test-csid-2"));
        when(crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                        request.getQueryStringParameters(), CLIENT_SESSION_ID))
                .thenReturn(Optional.of(crossBrowserEntity));
    }
}
