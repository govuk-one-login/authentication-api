package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
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
    private final JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
    private final JwksService jwksService =
            new JwksService(configurationService, kmsConnectionService, jwkSource);

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
    void shouldReturnMfaResetJarDeprecatedSigningKeyAndParseToJwk() {
        String mockKeyId = "123456789";
        when(configurationService.getMfaResetJarDeprecatedSigningKeyAlias()).thenReturn(mockKeyId);

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

        JWK publicKeyJwk = jwksService.getPublicMfaResetJarDeprecatedJwkWithOpaqueId();

        assertThat(publicKeyJwk.getKeyID(), equalTo(hashSha256String(mockKeyId)));
        assertThat(publicKeyJwk.getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        assertThat(publicKeyJwk.getKeyUse(), equalTo(KeyUse.SIGNATURE));
    }
}
