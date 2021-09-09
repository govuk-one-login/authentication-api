package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.TokenGeneratorHelper;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenValidationServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final TokenValidationService tokenValidationService =
            new TokenValidationService(
                    configurationService, redisConnectionService, kmsConnectionService);
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES = List.of("openid", "email", "phone");
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";

    @BeforeEach
    public void setUp() {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);
    }

    @Test
    public void shouldSuccessfullyValidateIDToken() throws JOSEException {
        ECKey ecJWK = generateECKeyPair();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecJWK);
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(KEY_ID);
        getPublicKeyResult.setSigningAlgorithms(
                Collections.singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(ByteBuffer.wrap(ecPublicJWK.toECPublicKey().getEncoded()));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);

        SignedJWT signedIdToken = createSignedIdToken(signer);
        assertTrue(tokenValidationService.validateIdTokenSignature(signedIdToken.serialize()));
    }

    @Test
    public void shouldSuccessfullyValidateAccessToken() throws JOSEException {
        ECKey ecJWK = generateECKeyPair();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecJWK);
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(KEY_ID);
        getPublicKeyResult.setSigningAlgorithms(
                Collections.singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(ByteBuffer.wrap(ecPublicJWK.toECPublicKey().getEncoded()));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);

        SignedJWT signedAccessToken = createSignedAccessToken(signer);
        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessToken.serialize())));
    }

    @Test
    public void shouldRetrievePublicKeyfromKmsAndParseToJwk() {
        String keyId = "3423543t5435345";
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(keyId);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(keyId);
        getPublicKeyResult.setSigningAlgorithms(
                Collections.singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(ByteBuffer.wrap(publicKey));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);
        JWK publicKeyJwk = tokenValidationService.getPublicJwk();
        assertEquals(publicKeyJwk.getKeyID(), keyId);
        assertEquals(publicKeyJwk.getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(publicKeyJwk.getKeyUse(), KeyUse.SIGNATURE);
    }

    private ECKey generateECKeyPair() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        } catch (JOSEException e) {
            throw new RuntimeException();
        }
    }

    private SignedJWT createSignedIdToken(JWSSigner signer) {
        return TokenGeneratorHelper.generateIDToken(CLIENT_ID, SUBJECT, BASE_URL, signer, KEY_ID);
    }

    private SignedJWT createSignedAccessToken(JWSSigner signer) {

        return TokenGeneratorHelper.generateAccessToken(
                CLIENT_ID, BASE_URL, SCOPES, signer, SUBJECT, KEY_ID);
    }
}
