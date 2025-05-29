package uk.gov.di.authentication.api;

import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.frontendapi.lambda.StartHandler;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.shared.services.SerializationService;

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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_REQUESTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_START_INFO_FOUND;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
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
    private static final Optional<String> WITH_PREVIOUS_SESSION = Optional.of(PREVIOUS_SESSION_ID);
    private static final Optional<String> NO_PREVIOUS_SESSION = Optional.empty();

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authAttemptsExtension =
            new AuthenticationAttemptsStoreExtension();

    @BeforeEach
    void setup() {
        handler = new StartHandler(new TestConfigurationService());
        txmaAuditQueue.clear();
    }

    private static Stream<Arguments> successfulRequests() {
        return Stream.of(
                Arguments.of(Optional.empty(), MEDIUM_LEVEL, false, false),
                Arguments.of(Optional.empty(), MEDIUM_LEVEL, false, true),
                Arguments.of(Optional.of(LevelOfConfidence.NONE), MEDIUM_LEVEL, false, false),
                Arguments.of(
                        Optional.of(LevelOfConfidence.MEDIUM_LEVEL), MEDIUM_LEVEL, true, false));
    }

    @ParameterizedTest
    @MethodSource("successfulRequests")
    void shouldReturn200AndStartResponse(
            Optional<LevelOfConfidence> requestedLevelOfConfidenceOpt,
            CredentialTrustLevel requestedCredentialTrustLevel,
            boolean identityRequired,
            boolean isAuthenticated)
            throws Json.JsonException {
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL, "password");
        authSessionExtension.addSession(PREVIOUS_SESSION_ID);
        authSessionExtension.addEmailToSession(PREVIOUS_SESSION_ID, EMAIL);
        authSessionExtension.addSession(sessionId);
        var state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);

        registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());
        var response =
                makeRequest(
                        Optional.of(
                                makeRequestBody(
                                        isAuthenticated,
                                        WITH_PREVIOUS_SESSION,
                                        state.getValue(),
                                        scope.toString(),
                                        REDIRECT_URI.toString(),
                                        requestedLevelOfConfidenceOpt,
                                        requestedCredentialTrustLevel)),
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
        var actualAuthSession = authSessionExtension.getSession(sessionId).orElseThrow();
        assertThat(
                actualAuthSession.getRequestedCredentialStrength(),
                equalTo(requestedCredentialTrustLevel));
        assertThat(
                actualAuthSession.getRequestedLevelOfConfidence(),
                equalTo(requestedLevelOfConfidenceOpt.orElse(null)));
        assertThat(actualAuthSession.getClientId(), equalTo(CLIENT_ID));
        assertThat(actualAuthSession.getClientName(), equalTo(TEST_CLIENT_NAME));
    }

    @Test
    void shouldReturn200AndStartResponseWithAuthenticatedFalseWhenReauthenticationIsRequested()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL, "password");
        authSessionExtension.addSession(sessionId);
        var state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);

        registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        var headers = standardHeadersWithSessionId(sessionId);
        headers.put("Reauthenticate", "true");

        var response =
                makeRequest(
                        Optional.of(
                                makeRequestBody(
                                        true,
                                        NO_PREVIOUS_SESSION,
                                        state.getValue(),
                                        scope.toString(),
                                        REDIRECT_URI.toString(),
                                        Optional.of(LevelOfConfidence.LOW_LEVEL),
                                        MEDIUM_LEVEL)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(200));

        StartResponse startResponse =
                objectMapper.readValue(response.getBody(), StartResponse.class);

        assertThat(startResponse.user().isAuthenticated(), equalTo(false));
        var actualAuthSession = authSessionExtension.getSession(sessionId).orElseThrow();
        assertThat(actualAuthSession.getRequestedCredentialStrength(), equalTo(MEDIUM_LEVEL));
        assertThat(
                actualAuthSession.getRequestedLevelOfConfidence(),
                equalTo(LevelOfConfidence.LOW_LEVEL));
        assertThat(actualAuthSession.getClientId(), equalTo(CLIENT_ID));
        assertThat(actualAuthSession.getClientName(), equalTo(TEST_CLIENT_NAME));
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
        authSessionExtension.addSession(PREVIOUS_SESSION_ID);
        authSessionExtension.addEmailToSession(PREVIOUS_SESSION_ID, userEmail);
        authSessionExtension.addSession(sessionId);

        userStore.signUp(userEmail, "rubbbishPassword");

        if (Objects.nonNull(mfaMethodType) && mfaMethodType.equals(MFAMethodType.SMS)) {
            userStore.addVerifiedPhoneNumber(userEmail, "+447316763843");
        } else if (Objects.nonNull(mfaMethodType) && mfaMethodType.equals(MFAMethodType.AUTH_APP)) {
            userStore.addMfaMethod(
                    userEmail, MFAMethodType.AUTH_APP, true, true, "rubbish-credential-value");
        }

        var state = new State();
        var scope = new Scope(OIDCScopeValue.OPENID);

        registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        var response =
                makeRequest(
                        Optional.of(
                                makeRequestBody(
                                        isAuthenticated,
                                        WITH_PREVIOUS_SESSION,
                                        state.getValue(),
                                        scope.toString(),
                                        REDIRECT_URI.toString(),
                                        Optional.empty(),
                                        MEDIUM_LEVEL)),
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

    @Test
    void shouldReturn400WhenRedirectURIIsInvalid() throws Exception {
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL, "password");
        authSessionExtension.addSession(sessionId);
        var state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);

        registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        var headers = standardHeadersWithSessionId(sessionId);
        headers.put("Reauthenticate", "true");

        var response =
                makeRequest(
                        Optional.of(
                                makeRequestBody(
                                        true,
                                        NO_PREVIOUS_SESSION,
                                        state.getValue(),
                                        scope.toString(),
                                        "invalid-redirect-uri/@'[]l.#,;][",
                                        Optional.of(LevelOfConfidence.LOW_LEVEL),
                                        MEDIUM_LEVEL)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(400));
        assertThat(response.getBody(), equalTo("Unable to parse redirect URI"));
    }

    @Test
    void userShouldNotComeBackAsAuthenticatedWhenSessionIsAuthenticatedButNoUserProfileExists()
            throws Json.JsonException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var isAuthenticated = true;
        var userEmail = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        var sessionId = redis.createSession();
        authSessionExtension.addSession(sessionId);
        registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        var response =
                makeRequest(
                        Optional.of(
                                makeRequestBody(
                                        isAuthenticated,
                                        NO_PREVIOUS_SESSION,
                                        STATE.getValue(),
                                        scope.toString(),
                                        REDIRECT_URI.toString(),
                                        Optional.empty(),
                                        MEDIUM_LEVEL)),
                        standardHeadersWithSessionId(sessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
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
        State state;
        Scope scope;

        @BeforeEach
        void setup() throws Json.JsonException {
            handler = new StartHandler(new TestConfigurationService());
            txmaAuditQueue.clear();
            sessionId = redis.createSession();
            userStore.signUp(EMAIL, "password");
            authSessionExtension.addSession(sessionId);
            state = new State();
            scope = new Scope();
            scope.add(OIDCScopeValue.OPENID);
            registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());
        }

        @Test
        void shouldAddSessionToDynamoWhenNoPreviousSessionIdIsProvidedInRequestBody() {
            makeRequest(
                    Optional.of(
                            makeRequestBody(
                                    false,
                                    NO_PREVIOUS_SESSION,
                                    state.getValue(),
                                    scope.toString(),
                                    REDIRECT_URI.toString(),
                                    Optional.of(LevelOfConfidence.LOW_LEVEL),
                                    MEDIUM_LEVEL)),
                    standardHeadersWithSessionId(sessionId),
                    Map.of());

            assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        }

        @Test
        void shouldReplaceSessionInDynamoWhenPreviousSessionIsProvidedInRequestBody() {
            authSessionExtension.addSession(PREVIOUS_SESSION_ID);
            assertThat(
                    authSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent(),
                    equalTo(true));

            makeRequest(
                    Optional.of(
                            makeRequestBody(
                                    false,
                                    WITH_PREVIOUS_SESSION,
                                    state.getValue(),
                                    scope.toString(),
                                    REDIRECT_URI.toString(),
                                    Optional.of(LevelOfConfidence.LOW_LEVEL),
                                    MEDIUM_LEVEL)),
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
                    Optional.of(
                            makeRequestBody(
                                    false,
                                    WITH_PREVIOUS_SESSION,
                                    state.getValue(),
                                    scope.toString(),
                                    REDIRECT_URI.toString(),
                                    Optional.of(LevelOfConfidence.LOW_LEVEL),
                                    MEDIUM_LEVEL)),
                    standardHeadersWithSessionId(sessionId),
                    Map.of());

            assertThat(
                    authSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent(),
                    equalTo(false));
            assertThat(authSessionExtension.getSession(sessionId).isPresent(), equalTo(true));
        }
    }

    @Nested
    class Uplift {
        String sessionId;
        State state = new State();
        Scope scope = new Scope();

        @BeforeEach
        void setup() throws Json.JsonException {
            handler = new StartHandler(new TestConfigurationService());
            txmaAuditQueue.clear();
            sessionId = IdGenerator.generate();
            redis.createSession(sessionId);
            userStore.signUp(EMAIL, "password");
            registerWebClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());
            scope.add(OIDCScopeValue.OPENID);
        }

        @Test
        void upliftNotRequiredWhenNoPreviousAuthSession() throws Json.JsonException {

            var response =
                    makeRequest(
                            Optional.of(
                                    makeRequestBody(
                                            false,
                                            NO_PREVIOUS_SESSION,
                                            state.getValue(),
                                            scope.toString(),
                                            REDIRECT_URI.toString(),
                                            Optional.of(LevelOfConfidence.LOW_LEVEL),
                                            MEDIUM_LEVEL)),
                            standardHeadersWithSessionId(sessionId),
                            Map.of());

            var startResponse = objectMapper.readValue(response.getBody(), StartResponse.class);
            assertFalse(startResponse.user().isUpliftRequired());
        }

        @ParameterizedTest
        @MethodSource("achievedAndRequestedStrengthValues")
        void upliftRequiredTestsWhenAuthSessionHasAchievedStrengthAndRpRequested(
                CredentialTrustLevel achievedCredentialStrength,
                CredentialTrustLevel requestedCredentialStrength,
                boolean isUpliftRequired)
                throws Json.JsonException {
            authSessionExtension.addSession(PREVIOUS_SESSION_ID);
            authSessionExtension.addAchievedCredentialTrustToSession(
                    PREVIOUS_SESSION_ID, achievedCredentialStrength);

            var response =
                    makeRequest(
                            Optional.of(
                                    makeRequestBody(
                                            false,
                                            WITH_PREVIOUS_SESSION,
                                            state.getValue(),
                                            scope.toString(),
                                            REDIRECT_URI.toString(),
                                            Optional.of(LevelOfConfidence.LOW_LEVEL),
                                            requestedCredentialStrength)),
                            standardHeadersWithSessionId(sessionId),
                            Map.of());

            var startResponse = objectMapper.readValue(response.getBody(), StartResponse.class);
            assertEquals(isUpliftRequired, startResponse.user().isUpliftRequired());
        }

        private static Stream<Arguments> achievedAndRequestedStrengthValues() {
            return Stream.of(
                    Arguments.of(null, MEDIUM_LEVEL, false),
                    Arguments.of(null, LOW_LEVEL, false),
                    Arguments.of(MEDIUM_LEVEL, LOW_LEVEL, false),
                    Arguments.of(LOW_LEVEL, LOW_LEVEL, false),
                    Arguments.of(LOW_LEVEL, MEDIUM_LEVEL, true));
        }
    }

    private String makeRequestBody(
            boolean isAuthenticated,
            Optional<String> previousSessionIdOpt,
            String state,
            String scope,
            String redirectUri,
            Optional<LevelOfConfidence> requestedLevelOfConfidenceOpt,
            CredentialTrustLevel requestedCredentialStrength) {
        Map<String, Object> requestBodyMap =
                new HashMap<>(
                        Map.of(
                                "authenticated",
                                isAuthenticated,
                                "state",
                                state,
                                "requested_credential_strength",
                                requestedCredentialStrength.getValue(),
                                "scope",
                                scope,
                                "client_id",
                                CLIENT_ID,
                                "redirect_uri",
                                redirectUri,
                                "client_name",
                                TEST_CLIENT_NAME));
        previousSessionIdOpt.ifPresent(
                previousSessionId -> requestBodyMap.put("previous-session-id", previousSessionId));
        requestedLevelOfConfidenceOpt.ifPresent(
                levelOfConfidence ->
                        requestBodyMap.put(
                                "requested_level_of_confidence", levelOfConfidence.getValue()));
        return SerializationService.getInstance().writeValueAsString(requestBodyMap);
    }

    private void registerWebClient(KeyPair keyPair) {
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
                ClientType.WEB,
                true);
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
