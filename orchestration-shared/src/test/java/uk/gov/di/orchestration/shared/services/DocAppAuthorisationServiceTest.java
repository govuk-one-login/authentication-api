package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.net.MalformedURLException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.shared.services.DocAppAuthorisationService.STATE_STORAGE_PREFIX;

class DocAppAuthorisationServiceTest {

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final State STATE = new State();
    private static final String SESSION_ID = "session-id";
    private static final Long SESSION_EXPIRY = 3600L;
    private static final String KEY_ID = "14342354354353";
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private static final URI DOC_APP_CALLBACK_URI =
            URI.create("http://localhost/oidc/doc-app/callback");
    private static final URI DOC_APP_AUTHORISATION_URI =
            URI.create("http://localhost/doc-app/authorize");
    private static final URI JWKS_URL =
            URI.create("http://localhost/doc-app/.well-known/jwks.json");
    private static final String ENCRYPTION_KID = UUID.randomUUID().toString();
    private static final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService = mock(JwksService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final DocAppAuthorisationService authorisationService =
            new DocAppAuthorisationService(
                    configurationService,
                    redisConnectionService,
                    kmsConnectionService,
                    jwksService,
                    stateStorageService);
    private PrivateKey privateKey;
    private RSAKey publicRsaKey;

    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);

    @BeforeEach
    void setUp() throws Json.JsonException, MalformedURLException, KeySourceException {
        when(configurationService.getDocAppJwksURI()).thenReturn(JWKS_URL);
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(objectMapper.writeValueAsString(STATE));
        when(configurationService.getDocAppAuthorisationClientId()).thenReturn(DOC_APP_CLIENT_ID);
        when(configurationService.getDocAppAuthorisationCallbackURI())
                .thenReturn(DOC_APP_CALLBACK_URI);
        when(configurationService.getDocAppAuthorisationURI())
                .thenReturn(DOC_APP_AUTHORISATION_URI);
        var keyPair = generateRsaKeyPair();
        privateKey = keyPair.getPrivate();
        publicRsaKey =
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
    void shouldReturnErrorObjectWhenStateInResponseIsDifferentToStoredState()
            throws Json.JsonException {
        State differentState = new State();
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(objectMapper.writeValueAsString(STATE));
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
    void shouldSaveStateToRedisAndDynamo() throws Json.JsonException {
        var sessionId = "session-id";
        authorisationService.storeState(sessionId, STATE);

        var prefixedSessionId = STATE_STORAGE_PREFIX + sessionId;
        verify(redisConnectionService)
                .saveWithExpiry(
                        prefixedSessionId, objectMapper.writeValueAsString(STATE), SESSION_EXPIRY);
        verify(stateStorageService).storeState(prefixedSessionId, STATE.getValue());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldConstructASignedRequestJWT(boolean isTestClient)
            throws JOSEException, ParseException, MalformedURLException {
        setupSigning();
        var state = new State();
        var pairwise = new Subject("pairwise-identifier");
        when(clientRegistry.isTestClient()).thenReturn(isTestClient);
        when(jwksService.getDocAppJwk()).thenReturn(publicRsaKey);

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
                            .after(NowHelper.nowPlus(3, ChronoUnit.MINUTES)),
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

    @Test
    void usesNewDocAppAudClaim() throws JOSEException, ParseException, MalformedURLException {
        when(configurationService.isDocAppNewAudClaimEnabled()).thenReturn(true);
        String newAudience = "https://www.review-b.test.account.gov.uk";
        when(configurationService.getDocAppAudClaim()).thenReturn(new Audience(newAudience));
        setupSigning();

        var state = new State();
        var pairwise = new Subject("pairwise-identifier");

        when(jwksService.getDocAppJwk()).thenReturn(publicRsaKey);
        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state, pairwise.getValue(), clientRegistry, "client-session-id");

        var signedJwt = decryptJWT(encryptedJWT);
        assertThat(signedJwt.getJWTClaimsSet().getAudience(), contains(newAudience));
    }

    private void setupSigning() throws JOSEException {
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
                        .keyId(KEY_ID)
                        .build();
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(privateKey));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
