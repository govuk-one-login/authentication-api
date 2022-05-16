package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
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
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTClaims;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
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

class IPVCallbackHandlerTest {

    private static final Subject SUBJECT = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final IPVAuthorisationService responseService = mock(IPVAuthorisationService.class);
    private final IPVTokenService ipvTokenService = mock(IPVTokenService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String REQUEST_ID = "a-request-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-id";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Subject PUBLIC_SUBJECT =
            new Subject("TsEVC7vg0NPAmzB33vRUFztL2c0-fecKWKcc73fuDhc");
    private static final State STATE = new State();
    private IPVCallbackHandler handler;
    private final byte[] salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
    private final String sectorId = "test.com";
    private final ClientRegistry clientRegistry = generateClientRegistry();
    private final UserProfile userProfile = generateUserProfile();

    private final Session session = new Session(SESSION_ID).setEmailAddress(TEST_EMAIL_ADDRESS);

    private final ClientSession clientSession =
            new ClientSession(generateAuthRequest().toParameters(), null, null);

    @BeforeEach
    void setUp() {
        handler =
                new IPVCallbackHandler(
                        configService,
                        responseService,
                        ipvTokenService,
                        sessionService,
                        dynamoService,
                        clientSessionService,
                        dynamoClientService,
                        auditService,
                        awsSqsClient);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URL));
        when(configService.isSpotEnabled()).thenReturn(true);
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.getIPVSector()).thenReturn(OIDC_BASE_URL + "/trustmark");

        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
    }

    @Test
    void shouldNotInvokeSPOTButStillRedirectToFrontendCallbackForSuccessfulResponseAtP0()
            throws URISyntaxException {

        usingValidSession();
        usingValidClientSession();

        var response = makeHandlerRequest(getApiGatewayProxyRequestEvent("P0"));

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("ipv-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoInteractions(awsSqsClient);
    }

    @Test
    void shouldInvokeSPOTAndRedirectToFrontendCallbackForSuccessfulResponseAtP2()
            throws URISyntaxException, JsonProcessingException {

        usingValidSession();
        usingValidClientSession();

        var response = makeHandlerRequest(getApiGatewayProxyRequestEvent("P2"));

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("ipv-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        var expectedPairwiseSub =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry, dynamoService);
        verify(awsSqsClient)
                .send(
                        ObjectMapperFactory.getInstance()
                                .writeValueAsString(
                                        new SPOTRequest(
                                                SPOTClaims.builder()
                                                        .withVot(
                                                                LevelOfConfidence.MEDIUM_LEVEL
                                                                        .getValue())
                                                        .withVtm(OIDC_BASE_URL + "/trustmark")
                                                        .build(),
                                                SUBJECT.getValue(),
                                                salt,
                                                sectorId,
                                                expectedPairwiseSub.getValue(),
                                                new LogIds(
                                                        session.getSessionId(),
                                                        PERSISTENT_SESSION_ID,
                                                        REQUEST_ID,
                                                        CLIENT_ID.getValue()))));

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldNotInvokeSPOTAndRedirectToFrontendCallbackForSuccessfulResponseAtP2WhenVTMMismatch()
            throws URISyntaxException, JsonProcessingException {

        usingValidSession();
        usingValidClientSession();

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent("P2", "http://invalid/trustmark"));

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("ipv-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        verifyNoInteractions(awsSqsClient);

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoMoreInteractions(auditService);
    }

    private void verifyAuditEvent(IPVAuditableEvent auditableEvent) {
        verify(auditService)
                .submitAuditEvent(
                        auditableEvent,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(String vot) {
        return getApiGatewayProxyRequestEvent(vot, OIDC_BASE_URL + "/trustmark");
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(String vot, String vtm) {
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(ipvTokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(ipvTokenService.sendTokenRequest(tokenRequest)).thenReturn(successfulTokenResponse);

        var userIdentityUserInfo =
                new UserInfo(new JSONObject(Map.of("sub", "sub-val", "vot", vot, "vtm", vtm)));
        when(ipvTokenService.sendIpvUserIdentityRequest(ArgumentMatchers.any()))
                .thenReturn(userIdentityUserInfo);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
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
    void shouldThrowWhenUserProfileNotFound() {
        usingValidSession();
        usingValidClientSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        RuntimeException expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(),
                equalTo("Email from session does not have a user profile"));

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
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
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

        assertThat(expectedException.getMessage(), equalTo("Error in IPV AuthorisationResponse"));

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowWhenClientRegistryIsNotFound() {
        usingValidSession();
        usingValidClientSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        RuntimeException expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(),
                equalTo("Client registry not found with given clientId"));

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowWhenTokenResponseIsNotSuccessful() {
        var salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
        var clientRegistry = generateClientRegistry();
        var userProfile = generateUserProfile();
        usingValidSession();
        usingValidClientSession();
        var unsuccessfulTokenResponse = new TokenErrorResponse(new ErrorObject("Error object"));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(ipvTokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(ipvTokenService.sendTokenRequest(tokenRequest)).thenReturn(unsuccessfulTokenResponse);

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
                containsString("IPV TokenResponse was not successful"));

        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);

        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        REQUEST_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);

        verifyNoMoreInteractions(auditService);
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(event, context);
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

    private void usingValidSession() {
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .setEmail(TEST_EMAIL_ADDRESS)
                .setEmailVerified(true)
                .setPhoneNumber("012345678902")
                .setPhoneNumberVerified(true)
                .setPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .setSubjectID(SUBJECT.getValue());
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .setClientID(CLIENT_ID.getValue())
                .setConsentRequired(false)
                .setClientName("test-client")
                .setRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("pairwise");
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
