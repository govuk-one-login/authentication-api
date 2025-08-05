package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
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

    @Test
    void shouldRetrievePublicTokenSigningKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");

        when(configurationService.getTokenSigningKeyAlias()).thenReturn("14342354354353");

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

        when(configurationService.getTokenSigningKeyRsaAlias()).thenReturn("25252525252525");

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
    void shouldRetrievePublicMfaResetStorageTokenSigningKeyFromKmsAndParseToJwk() {
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQjB7lXZryah6F/TgHVYro1tfifvMAOJsOa/kQzbOYjxGnAoGzW4NRJfn/K7caroQKYWTERFljryeSsaPFLXUOw==");

        System.out.println(publicKey);
        when(configurationService.getMfaResetStorageTokenSigningKeyAlias())
                .thenReturn("94542364374354");

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId("94542364374354")
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        System.out.println(result.signingAlgorithms());

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicMfaResetStorageTokenJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String("94542364374354")));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    @Test
    void shouldReturnMfaResetJarSigningKeyAndParseToJwk() {
        String mockKeyId = "123456789";
        when(configurationService.getMfaResetJarSigningKeyAlias()).thenReturn(mockKeyId);

        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9cKBC5iJvCv5TD5E+nqI0yes8bXlpqWza/cgYXX6QfL7xTjkgI7gblEYGctJgGTD8HbvO9pQX8n0H6+ibF4ewg==");

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId(mockKeyId)
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicMfaResetJarJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String(mockKeyId)));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }

    @Test
    void shouldReturnMfaResetJarSecondarySigningKeyAndParseToJwk() {
        String mockKeyId = "123456789";
        when(configurationService.getMfaResetJarSecondarySigningKeyAlias()).thenReturn(mockKeyId);

        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9cKBC5iJvCv5TD5E+nqI0yes8bXlpqWza/cgYXX6QfL7xTjkgI7gblEYGctJgGTD8HbvO9pQX8n0H6+ibF4ewg==");

        var result =
                GetPublicKeyResponse.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keyId(mockKeyId)
                        .signingAlgorithms(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .publicKey(SdkBytes.fromByteArray(publicKey))
                        .build();

        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(result);

        JWK publicKeyJwk = jwksService.getPublicMfaResetJarSecondaryJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String(mockKeyId)));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }
}
