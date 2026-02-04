package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.net.MalformedURLException;
import java.net.URI;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.shared.services.DocAppAuthorisationService.STATE_STORAGE_PREFIX;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class DocAppAuthorisationServiceTest {

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final State STATE = new State();
    private static final String SESSION_ID = "session-id";
    private static final Long SESSION_EXPIRY = 3600L;
    private static final String KEY_ID = "14342354354353";
    private static final String KEY_ALIAS = "test-key-alias";
    private static final String NEXT_KEY_ALIAS = "test-new-key-alias";
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private static final URI DOC_APP_CALLBACK_URI =
            URI.create("http://localhost/oidc/doc-app/callback");
    private static final URI DOC_APP_AUTHORISATION_URI =
            URI.create("http://localhost/doc-app/authorize");
    private static final URI JWKS_URL =
            URI.create("http://localhost/doc-app/.well-known/jwks.json");
    private static final String ENCRYPTION_KID = UUID.randomUUID().toString();
    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));
    private static final NowHelper.NowClock FIXED_NOW_HELPER = new NowHelper.NowClock(FIXED_CLOCK);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksCacheService jwksCacheService = mock(JwksCacheService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final DocAppAuthorisationService authorisationService =
            new DocAppAuthorisationService(
                    configurationService,
                    kmsConnectionService,
                    jwksCacheService,
                    stateStorageService,
                    FIXED_CLOCK);
    private PrivateKey privateEncryptionKey;
    private RSAKey publicEncryptionRsaKey;

    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);

    @BeforeEach
    void setUp() throws MalformedURLException {
        when(configurationService.getDocAppJwksUrl()).thenReturn(JWKS_URL.toURL());
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(stateStorageService.getState(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(
                        Optional.of(
                                new StateItem(STATE_STORAGE_PREFIX + SESSION_ID)
                                        .withState(STATE.getValue())));
        when(configurationService.getDocAppAuthorisationClientId()).thenReturn(DOC_APP_CLIENT_ID);
        when(configurationService.getDocAppAuthorisationCallbackURI())
                .thenReturn(DOC_APP_CALLBACK_URI);
        when(configurationService.getDocAppAuthorisationURI())
                .thenReturn(DOC_APP_AUTHORISATION_URI);
        var keyPair = generateRsaKeyPair();
        privateEncryptionKey = keyPair.getPrivate();
        publicEncryptionRsaKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(ENCRYPTION_KID)
                        .build();
    }

    @Test
    void shouldReturnOptionalEmptyWhenNoErrorIsPresent() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsError() {
        ErrorObject errorObject =
                new ErrorObject(
                        "invalid_request_redirect_uri", "redirect_uri param must be provided");
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(Optional.of(new ErrorObject(errorObject.getCode()))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoQueryParams() {
        assertThat(
                authorisationService.validateResponse(Collections.emptyMap(), SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No query parameters present"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoStateParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No state param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoCodeParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No code param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenNoStateFoundInDynamo() {
        when(stateStorageService.getState(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(Optional.empty());
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid state param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenStateInResponseIsDifferentToStoredState() {
        State differentState = new State();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", differentState.getValue());
        responseHeaders.put("code", AUTH_CODE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid state param present in Authorisation response"))));
    }

    @Test
    void shouldSaveStateToDynamo() {
        var sessionId = "session-id";
        authorisationService.storeState(sessionId, STATE);

        var prefixedSessionId = STATE_STORAGE_PREFIX + sessionId;
        verify(stateStorageService).storeState(prefixedSessionId, STATE.getValue());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldConstructASignedRequestJWT(boolean isTestClient)
            throws JOSEException, ParseException {
        setupSigning();
        var state = new State();
        var pairwise = new Subject("pairwise-identifier");
        when(clientRegistry.isTestClient()).thenReturn(isTestClient);
        when(jwksCacheService.getOrGenerateDocAppJwksCacheItem())
                .thenReturn(new JwksCacheItem(JWKS_URL.toString(), publicEncryptionRsaKey, 300));

        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state, pairwise.getValue(), clientRegistry, "client-session-id");

        var signedJWTResponse = decryptJWT(encryptedJWT);

        assertThat(
                signedJWTResponse.getJWTClaimsSet().getClaim("client_id"),
                equalTo(DOC_APP_CLIENT_ID));
        assertThat(
                signedJWTResponse.getJWTClaimsSet().getClaim("state"), equalTo(state.getValue()));
        assertThat(signedJWTResponse.getJWTClaimsSet().getSubject(), equalTo(pairwise.getValue()));
        assertThat(signedJWTResponse.getJWTClaimsSet().getIssuer(), equalTo(DOC_APP_CLIENT_ID));
        assertThat(
                signedJWTResponse.getJWTClaimsSet().getAudience(),
                equalTo(singletonList(DOC_APP_AUTHORISATION_URI.toString())));
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("response_type"), equalTo("code"));

        assertThat(
                signedJWTResponse.getJWTClaimsSet().getStringClaim("govuk_signin_journey_id"),
                equalTo("client-session-id"));
        assertThat(
                signedJWTResponse.getHeader().getKeyID(),
                equalTo(hashSha256String("789789789789789")));
        if (isTestClient) {
            assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("test_client"), equalTo(true));
            assertThat(
                    signedJWTResponse
                            .getJWTClaimsSet()
                            .getExpirationTime()
                            .after(FIXED_NOW_HELPER.nowPlus(3, ChronoUnit.MINUTES)),
                    equalTo(true));
        } else {
            assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("test_client"), equalTo(null));
            assertThat(
                    signedJWTResponse
                            .getJWTClaimsSet()
                            .getExpirationTime()
                            .before(NowHelper.nowPlus(3, ChronoUnit.MINUTES)),
                    equalTo(true));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSignWithCorrectKeyBasedOnFeatureFlag(boolean useNewSigningKey) throws JOSEException {
        when(configurationService.isUseNewDocAppSigningKey()).thenReturn(useNewSigningKey);
        when(configurationService.getDocAppTokenSigningKeyAlias()).thenReturn(KEY_ALIAS);
        when(configurationService.getNextDocAppTokenSigningKeyAlias()).thenReturn(NEXT_KEY_ALIAS);
        setupSigning(useNewSigningKey ? NEXT_KEY_ALIAS : KEY_ALIAS);

        var state = new State();
        var pairwise = new Subject("pairwise-identifier");
        when(jwksCacheService.getOrGenerateDocAppJwksCacheItem())
                .thenReturn(new JwksCacheItem(JWKS_URL.toString(), publicEncryptionRsaKey, 300));

        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state, pairwise.getValue(), clientRegistry, "client-session-id");

        var signedJWTResponse = decryptJWT(encryptedJWT);
        if (useNewSigningKey) {
            assertThat(
                    signedJWTResponse.getHeader().getKeyID(),
                    equalTo(hashSha256String(NEXT_KEY_ALIAS)));
            verify(kmsConnectionService)
                    .sign(argThat(signRequest -> NEXT_KEY_ALIAS.equals(signRequest.keyId())));
        } else {
            assertThat(
                    signedJWTResponse.getHeader().getKeyID(), equalTo(hashSha256String(KEY_ALIAS)));
            verify(kmsConnectionService)
                    .sign(argThat(signRequest -> KEY_ALIAS.equals(signRequest.keyId())));
        }
    }

    @Nested
    class Approvals {
        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldCreateRequestJWTWithExpectedClaims(boolean isTestClient)
                throws JOSEException, ParseException {
            setupSigning();
            var state = new State("state");
            var pairwise = new Subject("pairwise-identifier");
            when(clientRegistry.isTestClient()).thenReturn(isTestClient);
            when(jwksCacheService.getOrGenerateDocAppJwksCacheItem())
                    .thenReturn(
                            new JwksCacheItem(JWKS_URL.toString(), publicEncryptionRsaKey, 300));

            EncryptedJWT requestJWT;

            try (MockedStatic<IdGenerator> mockIdGenerator =
                    Mockito.mockStatic(IdGenerator.class)) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("jti");
                requestJWT =
                        authorisationService.constructRequestJWT(
                                state, pairwise.getValue(), clientRegistry, "client-session-id");
            }

            var signedJWTResponse = decryptJWT(requestJWT);

            JsonApprovals.verifyAsJson(
                    signedJWTResponse.getJWTClaimsSet().toJSONObject(),
                    org.approvaltests.Approvals.NAMES.withParameters(
                            isTestClient ? "forTestClient" : "forNonTestClient"));
        }
    }

    @Test
    void usesNewDocAppAudClaim() throws JOSEException, ParseException {
        when(configurationService.isDocAppNewAudClaimEnabled()).thenReturn(true);
        String newAudience = "https://www.review-b.test.account.gov.uk";
        when(configurationService.getDocAppAudClaim()).thenReturn(new Audience(newAudience));
        setupSigning();

        var state = new State();
        var pairwise = new Subject("pairwise-identifier");

        when(jwksCacheService.getOrGenerateDocAppJwksCacheItem())
                .thenReturn(new JwksCacheItem(JWKS_URL.toString(), publicEncryptionRsaKey, 300));
        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state, pairwise.getValue(), clientRegistry, "client-session-id");

        assertThat(encryptedJWT.getHeader().getKeyID(), equalTo(ENCRYPTION_KID));
        var signedJwt = decryptJWT(encryptedJWT);
        assertThat(signedJwt.getJWTClaimsSet().getAudience(), contains(newAudience));
    }

    private void setupSigning() throws JOSEException {
        setupSigning("789789789789789");
    }

    private void setupSigning(String keyAlias) throws JOSEException {
        when(configurationService.getDocAppTokenSigningKeyAlias()).thenReturn(keyAlias);
        when(kmsConnectionService.getPublicKey(
                        GetPublicKeyRequest.builder().keyId(keyAlias).build()))
                .thenReturn(GetPublicKeyResponse.builder().keyId(keyAlias).build());

        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet = new JWTClaimsSet.Builder().build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());

        var signResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(signatureToDER))
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .keyId(KEY_ALIAS)
                        .build();
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(privateEncryptionKey));
        return encryptedJWT.getPayload().toSignedJWT();
    }
}
