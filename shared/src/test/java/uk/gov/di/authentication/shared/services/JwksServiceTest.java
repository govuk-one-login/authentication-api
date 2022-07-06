package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Base64;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

class JwksServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService =
            new JwksService(configurationService, kmsConnectionService);
    private static final String KEY_ID = "14342354354353";
    private static final String HASHED_KEY_ID = hashSha256String(KEY_ID);
    private ECKey ecJWK;

    @BeforeEach
    void setUp() throws JOSEException {
        ecJWK = generateECKeyPair();
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(KEY_ID);
        getPublicKeyResult.setSigningAlgorithms(singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(
                ByteBuffer.wrap(ecJWK.toPublicJWK().toECPublicKey().getEncoded()));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);
    }

    @Test
    void shouldRetrievePublicTokenSigningKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");

        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);

        var result =
                new GetPublicKeyResult()
                        .withKeyUsage("SIGN_VERIFY")
                        .withKeyId(KEY_ID)
                        .withSigningAlgorithms(singletonList(JWSAlgorithm.ES256.getName()))
                        .withPublicKey(ByteBuffer.wrap(publicKey));

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicTokenJwkWithOpaqueId();

        assertEquals(publicKeyJwk.getKeyID(), HASHED_KEY_ID);
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
}
