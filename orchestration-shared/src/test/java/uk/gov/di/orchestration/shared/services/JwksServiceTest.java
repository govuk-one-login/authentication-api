package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.EncryptionJwkCache;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.util.Base64;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

class JwksServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService =
            new JwksService(configurationService, kmsConnectionService);

    @Test
    void shouldRetrievePublicTokenSigningKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");

        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn("14342354354353");

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId("14342354354353")
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        System.out.println(result.signingAlgorithms());

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicTokenJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String("14342354354353")));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    @Test
    void shouldRetrievePublicTokenSigningRsaKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKFDNUYzkMs+SY+SPqN+o+37hFVVF/CP3CRDsQB0Fxyn0gSY/UW0rJ5a4x8XyyD44PJhSfRt5ZmXe+lm+nD2iILIw/yOJDPW6T65eGmW5b4ewj8nH2ZcE1YhHybmY6hD/VMzPWbQKOR9xepIFO57EzLHyhEMvL6ONonQ1QFpon+QIDAQAB");

        when(configurationService.getExternalTokenSigningKeyRsaAlias())
                .thenReturn("25252525252525");

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId("25252525252525")
                        .signingAlgorithms(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        System.out.println(result.signingAlgorithms());

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicTokenRsaJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String("25252525252525")));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.RS256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    @Test
    void shouldUseJwkCacheToGetEncryptionKey() throws Exception {
        EncryptionJwkCache.getInstance().clear();
        URL testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
        int testTimeout = 123;
        when(configurationService.getIPVJwksUrl()).thenReturn(testJwksUrl);
        when(configurationService.getIPVJwkCacheExpirationInSeconds()).thenReturn(testTimeout);

        try (var mockJwksUtils = mockStatic(JwksUtils.class)) {
            JWK testKey1 = mock(JWK.class);
            when(testKey1.getKeyUse()).thenReturn(KeyUse.ENCRYPTION);
            when(testKey1.getAlgorithm()).thenReturn(JWEAlgorithm.RSA_OAEP_256);
            mockJwksUtils
                    .when(() -> JwksUtils.getKey(testJwksUrl, KeyUse.ENCRYPTION))
                    .thenReturn(testKey1);

            assertEquals(testKey1, jwksService.getIpvJwk());
        }
    }
}
