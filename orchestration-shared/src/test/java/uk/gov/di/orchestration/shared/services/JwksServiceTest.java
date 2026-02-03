package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

class JwksServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService =
            new JwksService(configurationService, kmsConnectionService);

    @Test
    void shouldRetrievePublicTokenSigningKeyFromKmsAndParseToJwk() throws Exception {
        var keyAlias = "14342354354353";
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(keyAlias);

        var publicKey = generateECKey().toPublicKey().getEncoded();
        mockKmsPublicKeyResponse(publicKey, keyAlias);

        JWK publicKeyJwk = jwksService.getPublicTokenJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String(keyAlias)));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    @Test
    void shouldRetrievePublicTokenSigningRsaKeyFromKmsAndParseToJwk() throws Exception {
        var keyAlias = "25252525252525";
        when(configurationService.getExternalTokenSigningKeyRsaAlias()).thenReturn(keyAlias);

        var publicKey = generateRsaKey().toPublicKey().getEncoded();
        mockKmsPublicKeyResponse(
                publicKey, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256, keyAlias);

        JWK publicKeyJwk = jwksService.getPublicTokenRsaJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String(keyAlias)));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.RS256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    private void mockKmsPublicKeyResponse(byte[] publicKey, String alias) {
        mockKmsPublicKeyResponse(publicKey, SigningAlgorithmSpec.ECDSA_SHA_256, alias);
    }

    private void mockKmsPublicKeyResponse(
            byte[] publicKey, SigningAlgorithmSpec signingAlgorithmSpec, String alias) {
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(
                        GetPublicKeyResponse.builder()
                                .keyUsage(KeyUsageType.SIGN_VERIFY)
                                .keyId(alias)
                                .signingAlgorithms(signingAlgorithmSpec)
                                .publicKey(SdkBytes.fromByteArray(publicKey))
                                .build());
    }

    private static ECKey generateECKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    }

    private static RSAKey generateRsaKey() throws Exception {
        return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    }
}
