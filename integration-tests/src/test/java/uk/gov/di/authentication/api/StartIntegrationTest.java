package uk.gov.di.authentication.api;

import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.frontendapi.lambda.StartHandler;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_REQUESTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_START_INFO_FOUND;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String TEST_CLIENT_NAME = "test-client-name";
    private static final State STATE = new State();
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    public static final String PREVIOUS_SESSION_ID = "4waJ14KA9IyxKzY7bIGIA3hUDos";
    public static final String REQUEST_BODY =
            "{\"previous-session-id\":\"4waJ14KA9IyxKzY7bIGIA3hUDos\", \"authenticated\": %s}";

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authAttemptsExtension =
            new AuthenticationAttemptsStoreExtension();

    @BeforeEach
    void setup() {
        handler = new StartHandler(new TestConfigurationService(), redisConnectionService);
        txmaAuditQueue.clear();
    }

    private static Stream<Arguments> successfulRequests() {
        return Stream.of(
                Arguments.of(Map.of(), false, false),
                Arguments.of(Map.of(), false, true),
                Arguments.of(Map.of("vtr", "[\"P0.Cl.Cm\"]"), false, false),
                Arguments.of(Map.of("vtr", "[\"P2.Cl.Cm\"]"), true, false));
    }

    @ParameterizedTest
    @MethodSource("successfulRequests")
    void shouldReturn200AndStartResponse(
            Map<String, String> customAuthParameters,
            boolean identityRequired,
            boolean isAuthenticated)
            throws Json.JsonException {
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL, "password");
        redis.addEmailToSession(sessionId, EMAIL);
        var state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(state);
        customAuthParameters.forEach(builder::customParameter);
        var authRequest = builder.build();

        redis.createClientSession(CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);
        var response =
                makeRequest(
                        Optional.of(makeRequestBody(isAuthenticated)),
                        standardHeadersWithSessionId(sessionId),
                        Map.of());
        assertThat(response, hasStatus(200));

        var user =
                format(
                        """
                {
                "upliftRequired":false,
                "identityRequired":%b,
                "authenticated":%b,
                "cookieConsent":null,
                "gaCrossDomainTrackingId":null,
                "docCheckingAppUser":false,
                "mfaMethodType":null,
                "isBlockedForReauth":false}
                """,
                        identityRequired, isAuthenticated);

        var client =
                format(
                        """
                {
                "clientName":"test-client-name",
                "scopes":["openid"],
                "serviceType":"MANDATORY",
                "cookieConsentShared":false,
                "redirectUri":"http://localhost/redirect",
                "state":"%s",
                "isOneLoginService":false
                }
                """,
                        state.getValue());

        var expectedJson =
                JsonParser.parseString(format("{\"user\": %s,\"client\": %s}", user, client));

        assertThat(JsonParser.parseString(response.getBody()), is(equalTo(expectedJson)));
        assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_START_INFO_FOUND));
    }

    @Test
    void shouldReturn200AndStartResponseWithAuthenticatedFalseWhenReauthenticationIsRequested()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL, "password");
        redis.addEmailToSession(sessionId, EMAIL);
        var state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(state);
        var authRequest = builder.build();

        redis.createClientSession(CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);

        var headers = standardHeadersWithSessionId(sessionId);
        headers.put("Reauthenticate", "true");

        var response = makeRequest(Optional.of(makeRequestBody(true)), headers, Map.of());
        assertThat(response, hasStatus(200));

        StartResponse startResponse =
                objectMapper.readValue(response.getBody(), StartResponse.class);

        assertThat(startResponse.user().isAuthenticated(), equalTo(false));
        assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_START_INFO_FOUND, AUTH_REAUTH_REQUESTED));
    }

    private static Stream<MFAMethodType> mfaMethodTypes() {
        return Stream.of(MFAMethodType.AUTH_APP, MFAMethodType.SMS, null);
    }

    @ParameterizedTest
    @MethodSource("mfaMethodTypes")
    void shouldReturn200WithCorrectMfaMethodTypeWhenTheseIsAnExistingSession(
            MFAMethodType mfaMethodType) throws Json.JsonException {
        var userEmail = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        var isAuthenticated = true;
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, userEmail);

        userStore.signUp(userEmail, "rubbbishPassword");

        if (Objects.nonNull(mfaMethodType) && mfaMethodType.equals(MFAMethodType.SMS)) {
            userStore.addVerifiedPhoneNumber(userEmail, "+447316763843");
        } else if (Objects.nonNull(mfaMethodType) && mfaMethodType.equals(MFAMethodType.AUTH_APP)) {
            userStore.addMfaMethod(
                    userEmail, MFAMethodType.AUTH_APP, true, true, "rubbish-credential-value");
        }

        var state = new State();
        var scope = new Scope(OIDCScopeValue.OPENID);
        var builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(state)
                        .customParameter("vtr", "[\"Cl.Cm\"]");
        var authRequest = builder.build();

        redis.createClientSession(CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);

        var response =
                makeRequest(
                        Optional.of(makeRequestBody(isAuthenticated)),
                        standardHeadersWithSessionId(sessionId),
                        Map.of());
        assertThat(response, hasStatus(200));

        StartResponse startResponse =
                objectMapper.readValue(response.getBody(), StartResponse.class);

        assertThat(startResponse.user().mfaMethodType(), equalTo(mfaMethodType));
        verifyStandardClientInformationSetOnResponse(startResponse.client(), scope, state);
        verifyStandardUserInformationSetOnResponse(startResponse.user());
        assertThat(startResponse.user().isAuthenticated(), equalTo(true));
        assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_START_INFO_FOUND));
    }

    @Test
    void shouldReturn400WhenClientSessionIdMissing() {
        var headers = Map.of("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.empty(), headers, Map.of());
        assertThat(response, hasStatus(400));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturn200WhenUserIsADocCheckingAppUser(boolean isAuthenticated)
            throws JOSEException, Json.JsonException {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        var state = new State();
        var sessionId = redis.createSession(isAuthenticated);
        var scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP),
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .requestObject(createSignedJWT(keyPair, state))
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());

        registerClient(keyPair, ClientType.APP);

        var response =
                makeRequest(
                        Optional.of(makeRequestBody(isAuthenticated)),
                        standardHeadersWithSessionId(sessionId),
                        Map.of());
        assertThat(response, hasStatus(200));

        var startResponse = objectMapper.readValue(response.getBody(), StartResponse.class);

        assertTrue(startResponse.user().isDocCheckingAppUser());
        assertFalse(startResponse.user().isAuthenticated());
        assertFalse(startResponse.user().isIdentityRequired());
        verifyStandardClientInformationSetOnResponse(startResponse.client(), scope, state);
        verifyStandardUserInformationSetOnResponse(startResponse.user());

        var clientSession = redis.getClientSession(CLIENT_SESSION_ID);

        assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_START_INFO_FOUND));
    }

    @Test
    void userShouldNotComeBackAsAuthenticatedWhenSessionIsAuthenticatedButNoUserProfileExists()
            throws Json.JsonException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var isAuthenticated = true;
        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(STATE)
                        .customParameter("vtr", "[\"Cl.Cm\"]")
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());
        var userEmail = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, userEmail);
        redis.addClientSessionIdToSession(CLIENT_SESSION_ID, sessionId);
        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);

        var response =
                makeRequest(
                        Optional.of(makeRequestBody(isAuthenticated)),
                        standardHeadersWithSessionId(sessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(redis.getSession(sessionId).isAuthenticated(), equalTo(false));
        var startResponse = objectMapper.readValue(response.getBody(), StartResponse.class);

        assertThat(startResponse.user().isAuthenticated(), equalTo(false));
        verifyStandardUserInformationSetOnResponse(startResponse.user());
        verifyStandardClientInformationSetOnResponse(startResponse.client(), scope, STATE);
        assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_START_INFO_FOUND));
    }

    @Nested
    class AuthSession {
        String sessionId;

        @BeforeEach
        void setup() throws Json.JsonException {
            handler = new StartHandler(new TestConfigurationService(), redisConnectionService);
            txmaAuditQueue.clear();
            sessionId = redis.createSession(false);
            userStore.signUp(EMAIL, "password");
            redis.addEmailToSession(sessionId, EMAIL);
            var state = new State();
            Scope scope = new Scope();
            scope.add(OIDCScopeValue.OPENID);
            var builder =
                    new AuthenticationRequest.Builder(
                                    ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                            .nonce(new Nonce())
                            .state(state);
            var authRequest = builder.build();
            redis.createClientSession(
                    CLIENT_SESSION_ID, TEST_CLIENT_NAME, authRequest.toParameters());
            registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);
        }

        @Test
        void shouldAddSessionToDynamoWhenNoPreviousSessionIdIsProvidedInRequestBody() {
            makeRequest(Optional.of("{}"), standardHeadersWithSessionId(sessionId), Map.of());

            assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        }

        @Test
        void shouldReplaceSessionInDynamoWhenPreviousSessionIsProvidedInRequestBody() {
            authSessionExtension.addSession(PREVIOUS_SESSION_ID);
            assertThat(
                    authSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent(),
                    equalTo(true));

            makeRequest(
                    Optional.of(makeRequestBody(false)),
                    standardHeadersWithSessionId(sessionId),
                    Map.of());

            assertThat(
                    authSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent(),
                    equalTo(false));
            assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        }

        @Test
        void shouldAddSessionToDynamoWhenPreviousSessionIsProvidedInRequestBodyButIsNotInDynamo() {
            makeRequest(
                    Optional.of(makeRequestBody(false)),
                    standardHeadersWithSessionId(sessionId),
                    Map.of());

            assertThat(
                    authSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent(),
                    equalTo(false));
            assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        }
    }

    private String makeRequestBody(boolean isAuthenticated) {
        return String.format(REQUEST_BODY, isAuthenticated);
    }

    private void registerClient(KeyPair keyPair, ClientType clientType) {
        clientStore.registerClient(
                CLIENT_ID,
                TEST_CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                List.of("openid", "email"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                clientType,
                true);
    }

    private SignedJWT createSignedJWT(KeyPair keyPair, State state) throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost")
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim(
                                "scope",
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP)
                                        .toString())
                        .claim("client_id", CLIENT_ID)
                        .claim("state", state.getValue())
                        .claim("nonce", new Nonce().getValue())
                        .issuer(CLIENT_ID)
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    private void verifyStandardClientInformationSetOnResponse(
            ClientStartInfo clientStartInfo, Scope scope, State state) {
        assertThat(clientStartInfo.clientName(), equalTo(TEST_CLIENT_NAME));
        assertThat(clientStartInfo.serviceType(), equalTo(ServiceType.MANDATORY.toString()));
        assertFalse(clientStartInfo.cookieConsentShared());
        assertThat(clientStartInfo.scopes(), equalTo(scope.toStringList()));
        assertThat(clientStartInfo.redirectUri(), equalTo(REDIRECT_URI));
        assertThat(clientStartInfo.state().getValue(), equalTo(state.getValue()));
    }

    private void verifyStandardUserInformationSetOnResponse(UserStartInfo userStartInfo) {
        assertThat(userStartInfo.isUpliftRequired(), equalTo(false));
        assertThat(userStartInfo.cookieConsent(), equalTo(null));
        assertThat(userStartInfo.gaCrossDomainTrackingId(), equalTo(null));
    }

    private Map<String, String> standardHeadersWithSessionId(String sessionId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);
        return headers;
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        public TestConfigurationService() {
            super(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }
    }
}
