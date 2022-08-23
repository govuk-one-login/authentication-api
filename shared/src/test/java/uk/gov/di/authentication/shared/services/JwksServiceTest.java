package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.Base64;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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

    @BeforeEach
    void setUp() throws JOSEException {
        var ecJWK = generateECKeyPair();
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        var getPublicKeyResponse =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId(KEY_ID)
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(
                                SdkBytes.fromByteArray(
                                        ecJWK.toPublicJWK().toECPublicKey().getEncoded()))
                        .build();
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResponse);
    }

    @Test
    void shouldRetrievePublicTokenSigningKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");

        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId(KEY_ID)
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicTokenJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(HASHED_KEY_ID));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    private ECKey generateECKeyPair() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        } catch (JOSEException e) {
            throw new RuntimeException();
        }
    }
}
