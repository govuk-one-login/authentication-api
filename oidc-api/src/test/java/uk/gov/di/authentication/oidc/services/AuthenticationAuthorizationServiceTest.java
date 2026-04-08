package uk.gov.di.authentication.oidc.services;

import com.google.gson.GsonBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationAuthorisationRequestException;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static java.time.Clock.fixed;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.entity.AuthErrorCodes.SFAD_ERROR;
import static uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX;
import static uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService.GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.EMAIL;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.EMAIL_VERIFIED;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.LEGACY_SUBJECT_ID;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.LOCAL_ACCOUNT_ID;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.PHONE_NUMBER;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.PUBLIC_SUBJECT_ID;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.SALT;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.UPLIFT_REQUIRED;
import static uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class AuthenticationAuthorizationServiceTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final OrchestrationAuthorizationService orchestrationAuthorizationService =
            mock(OrchestrationAuthorizationService.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private AuthenticationAuthorizationService authService;
    private static final State STORED_STATE = new State();
    private static final String SESSION_ID = "a-session-id";
    private static final String EXAMPLE_AUTH_CODE = "any-text-will-do";
    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock fixedClock = fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));
    private static final NowHelper.NowClock fixedNowClock = new NowHelper.NowClock(fixedClock);
    private final OrchSessionItem orchSession = new OrchSessionItem(SESSION_ID);
    private static final Subject SUBJECT = new Subject("test-subject");
    private static final URI FRONT_END_BASE_URI = URI.create("https://example.com");
    private static final String TEST_ORCHESTRATOR_CLIENT_ID = "test-orch-client-id";
    private static final String ORCH_REDIRECT_URI = "https://example/orchestration-redirect";

    @BeforeEach
    void setUp() {
        when(stateStorageService.getState(anyString()))
                .thenReturn(
                        Optional.of(
                                new StateItem(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID)
                                        .withState(STORED_STATE.getValue())));
        when(configurationService.isSingleFactorAccountDeletionEnabled()).thenReturn(false);
        when(configurationService.getOrchestrationClientId())
                .thenReturn(TEST_ORCHESTRATOR_CLIENT_ID);
        when(configurationService.getOrchestrationRedirectURI()).thenReturn(ORCH_REDIRECT_URI);
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        when(authFrontend.baseURI()).thenReturn(FRONT_END_BASE_URI);
        when(authFrontend.authorizeURI(any(), any())).thenReturn(FRONT_END_BASE_URI);
        when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(true);
        authService =
                new AuthenticationAuthorizationService(
                        configurationService,
                        stateStorageService,
                        orchestrationAuthorizationService,
                        tokenValidationService,
                        authFrontend,
                        fixedNowClock);
    }

    @Nested
    class GenerateAuthRedirectRequest {
        private static final VectorOfTrust AUTH_ONLY_VTR =
                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.NONE);
        private static final VectorOfTrust IDENTITY_VTR =
                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);
        private ClientRegistry clientRegistry = generateClientRegistry();
        private static final ClientID CLIENT_ID = new ClientID("test-id");
        private static final String PREVIOUS_SESSION_ID = "previous-session-id";
        private static final String CLIENT_SESSION_ID = "a-client-session-id";
        private static final String PREVIOUS_CLIENT_SESSION_ID = "previous-client-session-id";
        private static final String REDIRECT_URI = "https://localhost:8080";
        private static final String SCOPE = "email openid profile";
        private static final String CLIENT_NAME = "test-rp-client-name";
        private static final String RP_SECTOR_HOST_URL = "https://test.com";
        private static final String RP_SECTOR_HOST = "test.com";
        private static final Boolean IS_ONE_LOGIN = false;
        private static final Boolean IS_COOKIE_CONSENT_SHARED = false;
        private static final String RP_SERVICE_TYPE = "MANDATORY";
        private static final String RP_SUBJECT_TYPE = "pairwise";
        private static final State STATE = new State("rp-state");
        private static final Nonce NONCE = new Nonce();

        @RegisterExtension
        public final CaptureLoggingExtension logging =
                new CaptureLoggingExtension(AuthorisationHandler.class);

        @Test
        void shouldGenerateAuthRedirectRequestForAuthJourney() throws Exception {
            var authRequest = generateAuthRequest(AUTH_ONLY_VTR);
            var authRedirectRequest =
                    authService.generateAuthRedirectRequest(
                            SESSION_ID,
                            CLIENT_SESSION_ID,
                            authRequest,
                            clientRegistry,
                            false,
                            AUTH_ONLY_VTR,
                            Optional.empty(),
                            orchSession);

            assertThat(authRedirectRequest.getResponseType(), equalTo(ResponseType.CODE));
            assertThat(
                    authRedirectRequest.getClientID().getValue(),
                    equalTo(TEST_ORCHESTRATOR_CLIENT_ID));
            assertThat(
                    authRedirectRequest.getEndpointURI().toString(),
                    startsWith(FRONT_END_BASE_URI.toString()));
            verify(orchestrationAuthorizationService)
                    .storeState(
                            eq(SESSION_ID),
                            eq(CLIENT_SESSION_ID),
                            argThat(state -> !STATE.getValue().equals(state.getValue())));
            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("requested_credential_strength"), equalTo("Cl"));

            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertRequiredUserInfoClaimsAreSet(actualUserInfoClaims);
        }

        @Test
        void shouldGenerateAuthRedirectRequestForIdentityJourney() throws Exception {
            var authRequest = generateAuthRequest(IDENTITY_VTR);
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    IDENTITY_VTR,
                    Optional.empty(),
                    orchSession);

            verify(orchestrationAuthorizationService)
                    .storeState(
                            eq(SESSION_ID),
                            eq(CLIENT_SESSION_ID),
                            argThat(state -> !STATE.getValue().equals(state.getValue())));
            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("requested_credential_strength"), equalTo("Cl.Cm"));
            assertThat(claimsSet.getClaim("requested_level_of_confidence"), equalTo("P2"));

            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertRequiredUserInfoClaimsAreSet(actualUserInfoClaims);
            assertTrue(actualUserInfoClaims.containsKey(PHONE_NUMBER.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(SALT.getValue()));
        }

        @Test
        void shouldGenerateAuthRedirectRequestForReauthJourney() throws Exception {
            var ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            var reauthToken =
                    TokenGeneratorHelper.generateIDToken(
                            CLIENT_ID.getValue(),
                            SUBJECT,
                            "http://localhost",
                            PREVIOUS_CLIENT_SESSION_ID,
                            ecSigningKey);
            var authRequest =
                    generateAuthRequestForReauthJourney(reauthToken.serialize(), AUTH_ONLY_VTR);
            when(tokenValidationService.isTokenSignatureValid(anyString())).thenReturn(true);

            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    true,
                    AUTH_ONLY_VTR,
                    Optional.of(PREVIOUS_SESSION_ID),
                    orchSession);

            verify(orchestrationAuthorizationService)
                    .storeState(
                            eq(SESSION_ID),
                            eq(CLIENT_SESSION_ID),
                            argThat(state -> !STATE.getValue().equals(state.getValue())));

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("requested_credential_strength"), equalTo("Cl"));
            assertThat(claimsSet.getClaim("previous_session_id"), equalTo(PREVIOUS_SESSION_ID));
            assertThat(claimsSet.getClaim("reauthenticate"), equalTo(SUBJECT.getValue()));
            assertThat(
                    claimsSet.getClaim("previous_govuk_signin_journey_id"),
                    equalTo(PREVIOUS_CLIENT_SESSION_ID));

            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertRequiredUserInfoClaimsAreSet(actualUserInfoClaims);
        }

        @Test
        void shouldThrowExceptionWhenReauthTokenSignatureInvalid() throws Exception {
            var authRequest =
                    generateAuthRequestForReauthJourney(
                            "reauth-token-with-invalid-signature", AUTH_ONLY_VTR);
            when(tokenValidationService.isTokenSignatureValid(anyString())).thenReturn(false);

            assertThrows(
                    AuthenticationAuthorisationRequestException.class,
                    () ->
                            authService.generateAuthRedirectRequest(
                                    SESSION_ID,
                                    CLIENT_SESSION_ID,
                                    authRequest,
                                    clientRegistry,
                                    true,
                                    AUTH_ONLY_VTR,
                                    Optional.of(PREVIOUS_SESSION_ID),
                                    orchSession));
        }

        @Test
        void shouldThrowExceptionWhenReauthTokenCouldNotBeParsed() throws Exception {
            var authRequest =
                    generateAuthRequestForReauthJourney("invalid-reauth-token", AUTH_ONLY_VTR);
            when(tokenValidationService.isTokenSignatureValid(anyString())).thenReturn(true);

            assertThrows(
                    AuthenticationAuthorisationRequestException.class,
                    () ->
                            authService.generateAuthRedirectRequest(
                                    SESSION_ID,
                                    CLIENT_SESSION_ID,
                                    authRequest,
                                    clientRegistry,
                                    true,
                                    AUTH_ONLY_VTR,
                                    Optional.of(PREVIOUS_SESSION_ID),
                                    orchSession));
        }

        @Test
        void shouldThrowExceptionWhenReauthTokenAudIsDifferentToClientIdInAuthRequest()
                throws Exception {
            var ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            var reauthToken =
                    TokenGeneratorHelper.generateIDToken(
                            "a-different-client-id",
                            SUBJECT,
                            "http://localhost",
                            PREVIOUS_CLIENT_SESSION_ID,
                            ecSigningKey);
            var authRequest =
                    generateAuthRequestForReauthJourney(reauthToken.serialize(), AUTH_ONLY_VTR);
            when(tokenValidationService.isTokenSignatureValid(anyString())).thenReturn(true);

            assertThrows(
                    AuthenticationAuthorisationRequestException.class,
                    () ->
                            authService.generateAuthRedirectRequest(
                                    SESSION_ID,
                                    CLIENT_SESSION_ID,
                                    authRequest,
                                    clientRegistry,
                                    true,
                                    AUTH_ONLY_VTR,
                                    Optional.of(PREVIOUS_SESSION_ID),
                                    orchSession));
        }

        private static Stream<Arguments> clientChannelsAndExpectedChannels() {
            return Stream.of(
                    arguments(null, null, Channel.WEB.getValue()),
                    arguments(null, Channel.WEB.getValue(), Channel.WEB.getValue()),
                    arguments(
                            null,
                            Channel.STRATEGIC_APP.getValue(),
                            Channel.STRATEGIC_APP.getValue()),
                    arguments(null, Channel.GENERIC_APP.getValue(), Channel.GENERIC_APP.getValue()),
                    arguments(Channel.WEB.getValue(), null, Channel.WEB.getValue()),
                    arguments(Channel.GENERIC_APP.getValue(), null, Channel.GENERIC_APP.getValue()),
                    arguments(
                            Channel.GENERIC_APP.getValue(),
                            Channel.WEB.getValue(),
                            Channel.GENERIC_APP.getValue()));
        }

        @ParameterizedTest
        @MethodSource("clientChannelsAndExpectedChannels")
        void shouldPassTheCorrectChannelClaimToAuth(
                String authRequestChannel, String clientChannel, String expectedChannelClaim)
                throws Exception {
            clientRegistry.setChannel(clientChannel);

            AuthenticationRequest authRequest;
            if (authRequestChannel != null) {
                authRequest =
                        authRequestBuilder(AUTH_ONLY_VTR)
                                .customParameter("channel", authRequestChannel)
                                .build();
            } else {
                authRequest = generateAuthRequest(AUTH_ONLY_VTR);
            }
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("channel"), equalTo(expectedChannelClaim));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldPassAuthenticatedClaimToAuthFromOrchSession(boolean isAuthenticated)
                throws Exception {
            orchSession.setAuthenticated(isAuthenticated);
            var authRequest = generateAuthRequest(AUTH_ONLY_VTR);
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("authenticated"), equalTo(isAuthenticated));
        }

        @Test
        void shouldAddPublicSubjectIdClaimIfClientHasPublicSubjectTypePresent() throws Exception {
            clientRegistry = generateClientRegistry().withSubjectType(PUBLIC.toString());
            var authRequest = generateAuthRequest(AUTH_ONLY_VTR);
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("subject_type"), equalTo(PUBLIC.toString()));
            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertRequiredUserInfoClaimsAreSet(actualUserInfoClaims);
            assertTrue(actualUserInfoClaims.containsKey(PUBLIC_SUBJECT_ID.getValue()));
        }

        @Test
        void shouldAddPublicSubjectIdClaimIfAuthRequestHasAmScope() throws Exception {
            var authRequest =
                    authRequestBuilder(AUTH_ONLY_VTR).scope(Scope.parse("openid am")).build();
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertTrue(actualUserInfoClaims.containsKey(PUBLIC_SUBJECT_ID.getValue()));
        }

        @Test
        void shouldAddLegacySubjectIdClaimIfGovUkAccountScopePresent() throws Exception {
            clientRegistry = generateClientRegistry().withSubjectType(PUBLIC.toString());
            var authRequest =
                    authRequestBuilder(AUTH_ONLY_VTR)
                            .scope(Scope.parse("openid govuk-account"))
                            .build();
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertRequiredClaimsAreSet(claimsSet);
            assertThat(claimsSet.getClaim("scope"), equalTo("openid govuk-account"));
            var actualUserinfo =
                    SerializationService.getInstance()
                            .readValue(claimsSet.getClaim("claim").toString(), Map.class);
            var actualUserInfoClaims = (Map<String, String>) actualUserinfo.get("userinfo");
            assertTrue(actualUserInfoClaims.containsKey(LEGACY_SUBJECT_ID.getValue()));
        }

        @Test
        void shouldRedirectToLoginWithPromptParamWhenSetToLogin() throws Exception {
            var authRequest = authRequestBuilder(AUTH_ONLY_VTR).prompt(Prompt.Type.LOGIN).build();
            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            verify(authFrontend).authorizeURI(Optional.of(Prompt.Type.LOGIN), Optional.empty());
        }

        @Test
        void shouldRetainGoogleAnalyticsParamThroughRedirectToLogin() throws Exception {
            var authRequest =
                    authRequestBuilder(AUTH_ONLY_VTR)
                            .customParameter(GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY, "test")
                            .build();

            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            verify(authFrontend).authorizeURI(Optional.empty(), Optional.of("test"));
        }

        @Test
        void shouldSendAuthTheClaimsRequiredWhenIdentityRequested() throws Exception {
            try (MockedStatic<IdGenerator> mockIdGenerator = mockStatic(IdGenerator.class);
                    MockedConstruction<State> ignored =
                            Mockito.mockConstruction(
                                    State.class,
                                    (mock, context) -> when(mock.getValue()).thenReturn("state"))) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                var authRequest = generateAuthRequest(IDENTITY_VTR);
                authService.generateAuthRedirectRequest(
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        authRequest,
                        clientRegistry,
                        false,
                        IDENTITY_VTR,
                        Optional.of(PREVIOUS_SESSION_ID),
                        orchSession);

                var jwtClaimSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
                verify(orchestrationAuthorizationService)
                        .getSignedAndEncryptedJWT(jwtClaimSetCaptor.capture());

                JsonApprovals.verifyAsJson(
                        jwtClaimSetCaptor.getValue().toJSONObject(), GsonBuilder::serializeNulls);
            }
        }

        @Test
        void shouldSendAuthTheRequiredClaimsWhenAuthOnly() throws Exception {
            var authRequest = generateAuthRequest(AUTH_ONLY_VTR);
            try (MockedStatic<IdGenerator> mockIdGenerator = mockStatic(IdGenerator.class);
                    MockedConstruction<State> ignored =
                            Mockito.mockConstruction(
                                    State.class,
                                    (mock, context) -> when(mock.getValue()).thenReturn("state"))) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                authService.generateAuthRedirectRequest(
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        authRequest,
                        clientRegistry,
                        false,
                        AUTH_ONLY_VTR,
                        Optional.of(PREVIOUS_SESSION_ID),
                        orchSession);

                var jwtClaimSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
                verify(orchestrationAuthorizationService)
                        .getSignedAndEncryptedJWT(jwtClaimSetCaptor.capture());

                JsonApprovals.verifyAsJson(
                        jwtClaimSetCaptor.getValue().toJSONObject(), GsonBuilder::serializeNulls);
            }
        }

        @Test
        void shouldNotAddReauthenticateOrPreviousJourneyIdClaimIfReauthRequestedFalse()
                throws Exception {
            var authRequest = generateAuthRequest(AUTH_ONLY_VTR);

            authService.generateAuthRedirectRequest(
                    SESSION_ID,
                    CLIENT_SESSION_ID,
                    authRequest,
                    clientRegistry,
                    false,
                    AUTH_ONLY_VTR,
                    Optional.empty(),
                    orchSession);

            var claimsSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(claimsSetCaptor.capture());
            var claimsSet = claimsSetCaptor.getValue();
            assertNull(claimsSet.getClaim("reauthenticate"));
            assertNull(claimsSet.getClaim("previous_govuk_signin_journey_id"));
        }

        private void assertRequiredUserInfoClaimsAreSet(Map<String, String> actualUserInfoClaims) {
            assertTrue(actualUserInfoClaims.containsKey(EMAIL.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(LOCAL_ACCOUNT_ID.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(VERIFIED_MFA_METHOD_TYPE.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(UPLIFT_REQUIRED.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(ACHIEVED_CREDENTIAL_STRENGTH.getValue()));
            assertTrue(actualUserInfoClaims.containsKey(EMAIL_VERIFIED.getValue()));
        }

        private void assertRequiredClaimsAreSet(JWTClaimsSet claimsSet) throws Exception {
            assertThat(claimsSet.getIssuer(), equalTo(TEST_ORCHESTRATOR_CLIENT_ID));
            assertThat(claimsSet.getAudience().get(0), equalTo(FRONT_END_BASE_URI.toString()));
            assertThat(claimsSet.getClaim("rp_client_id"), equalTo(CLIENT_ID.getValue()));
            assertThat(claimsSet.getClaim("rp_sector_host"), equalTo(RP_SECTOR_HOST));
            assertThat(claimsSet.getClaim("rp_redirect_uri"), equalTo(new URI(REDIRECT_URI)));
            assertThat(claimsSet.getClaim("rp_state"), equalTo(STATE.toString()));
            assertThat(claimsSet.getClaim("client_name"), equalTo(CLIENT_NAME));
            assertThat(
                    claimsSet.getClaim("cookie_consent_shared"), equalTo(IS_COOKIE_CONSENT_SHARED));
            assertThat(claimsSet.getClaim("is_one_login_service"), equalTo(IS_ONE_LOGIN));
            assertThat(claimsSet.getClaim("service_type"), equalTo(RP_SERVICE_TYPE));
            assertThat(claimsSet.getClaim("govuk_signin_journey_id"), equalTo(CLIENT_SESSION_ID));
            assertThat(claimsSet.getClaim("redirect_uri"), equalTo(ORCH_REDIRECT_URI));
        }

        private AuthenticationRequest.Builder authRequestBuilder(VectorOfTrust vtr)
                throws Exception {
            Scope scope = Scope.parse(SCOPE);
            return new AuthenticationRequest.Builder(
                            ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                    .state(STATE)
                    .nonce(NONCE)
                    .redirectionURI(new URI(REDIRECT_URI))
                    .customParameter(
                            "vtr",
                            jsonArrayOf(
                                    vtr.getCredentialTrustLevel().getValue()
                                            + "."
                                            + vtr.getLevelOfConfidence().getValue()));
        }

        private AuthenticationRequest generateAuthRequest(VectorOfTrust vtr) throws Exception {
            return authRequestBuilder(vtr).build();
        }

        private AuthenticationRequest generateAuthRequestForReauthJourney(
                String reauthToken, VectorOfTrust vtr) throws Exception {
            return authRequestBuilder(vtr)
                    .customParameter("id_token_hint", reauthToken)
                    .prompt(Prompt.Type.LOGIN)
                    .build();
        }

        private ClientRegistry generateClientRegistry() {
            return new ClientRegistry()
                    .withClientID("test-id")
                    .withCookieConsentShared(IS_COOKIE_CONSENT_SHARED)
                    .withClientName(CLIENT_NAME)
                    .withSectorIdentifierUri(RP_SECTOR_HOST_URL)
                    .withRedirectUrls(List.of(REDIRECT_URI))
                    .withOneLoginService(IS_ONE_LOGIN)
                    .withServiceType(RP_SERVICE_TYPE)
                    .withSubjectType(RP_SUBJECT_TYPE)
                    .withIdentityVerificationSupported(true)
                    .withMaxAgeEnabled(false);
        }
    }

    @Nested
    class Callback {
        @Test
        void shouldValidateRequestWithValidParams() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STORED_STATE.getValue());
            queryParams.put("code", EXAMPLE_AUTH_CODE);

            assertDoesNotThrow(() -> authService.validateRequest(queryParams, SESSION_ID, false));
            verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
        }

        @Test
        void shouldThrowWhenNoQueryParametersPresent() {
            Map<String, String> queryParams = new HashMap<>();

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
            verify(stateStorageService, never()).getState(anyString());
        }

        @Test
        void shouldThrowWhenErrorParamPresent() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", "some-error");

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
            verify(stateStorageService, never()).getState(anyString());
        }

        @ParameterizedTest
        @MethodSource("reauthErrorCases")
        void shouldThrowWhenErrorParamPresent(
                String reauthErrorCode, ErrorObject expectedErrorObject) {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", reauthErrorCode);

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(exception.getError(), is((equalTo(expectedErrorObject))));
            assertThat(exception.getLogoutRequired(), is((equalTo(true))));
            verify(stateStorageService, never()).getState(anyString());
        }

        static Stream<Arguments> reauthErrorCases() {
            return Stream.of(
                    Arguments.of(OAuth2Error.ACCESS_DENIED_CODE, OAuth2Error.ACCESS_DENIED),
                    Arguments.of(OIDCError.LOGIN_REQUIRED_CODE, OIDCError.LOGIN_REQUIRED));
        }

        @Test
        void shouldThrowWhenNoStateParamPresent() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("code", EXAMPLE_AUTH_CODE);

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
            verify(stateStorageService, never()).getState(anyString());
        }

        @Test
        void shouldThrowWhenStateParamDoesNotMatchStoredState() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", new State().getValue());
            queryParams.put("code", EXAMPLE_AUTH_CODE);

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(
                    exception.getError(),
                    samePropertyValuesAs(
                            new ErrorObject(
                                    ACCESS_DENIED_CODE,
                                    "Access denied for security reasons, a new authentication request may be successful")));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
            verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
        }

        @Test
        void shouldThrowWhenNoStateFoundInDynamo() {
            when(stateStorageService.getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID))
                    .thenReturn(Optional.empty());
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", new State().getValue());
            queryParams.put("code", EXAMPLE_AUTH_CODE);

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(
                    exception.getError(),
                    samePropertyValuesAs(
                            new ErrorObject(
                                    ACCESS_DENIED_CODE,
                                    "Access denied for security reasons, a new authentication request may be successful")));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
            verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
        }

        @Test
        void shouldThrowWhenNoCodeParamPresent() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STORED_STATE.getValue());

            var exception =
                    assertThrows(
                            AuthenticationCallbackValidationException.class,
                            () -> authService.validateRequest(queryParams, SESSION_ID, false));
            assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
            assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        }
    }

    @Test
    void shouldThrowWhenSingleFactorAccountDeletionErrorReceivedAndOnReauthJourney() {
        when(configurationService.isSingleFactorAccountDeletionEnabled()).thenReturn(true);
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", SFAD_ERROR.toString());

        assertThrows(
                AuthenticationCallbackValidationException.class,
                () -> authService.validateRequest(queryParams, SESSION_ID, true));
    }

    @Test
    void shouldNotThrowWhenSingleFactorAccountDeletionErrorReceivedAndNotOnReauthJourney() {
        when(configurationService.isSingleFactorAccountDeletionEnabled()).thenReturn(true);
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", SFAD_ERROR.toString());

        assertDoesNotThrow(() -> authService.validateRequest(queryParams, SESSION_ID, false));
    }
}
