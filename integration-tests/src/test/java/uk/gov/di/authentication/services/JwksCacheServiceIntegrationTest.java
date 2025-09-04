package uk.gov.di.authentication.services;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.utils.JwksUtils;
import uk.gov.di.orchestration.sharedtest.extensions.JwksCacheExtension;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

public class JwksCacheServiceIntegrationTest {
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final String JWKS_URL = "http://localhost/.well-known/jwks.json";

    @RegisterExtension
    public static final JwksCacheExtension jwksCacheExtension = new JwksCacheExtension();

    @Test
    void shouldGetFirstKeyIfMultipleSigningKeys() {
        var jwk1 = createPublicJwk("test-enc-key-1");
        var jwk2 = createPublicJwk("test-enc-key-2");
        var key1 = new JwksCacheItem(JWKS_URL, jwk1, VALID_TTL);
        var key2 = new JwksCacheItem(JWKS_URL, jwk2, VALID_TTL);

        jwksCacheExtension.putJwksCacheItem(key1);
        jwksCacheExtension.putJwksCacheItem(key2);

        var encKey = jwksCacheExtension.getOrGenerateJwksCacheItem();

        assertEquals("test-enc-key-1", encKey.getKeyId());
    }

    @Test
    void shouldGenerateFirstKeyIfNoSigningKeys() {
        try (MockedStatic<JwksUtils> mockedJwksUtilsClass = Mockito.mockStatic(JwksUtils.class)) {
            mockedJwksUtilsClass
                    .when(() -> JwksUtils.getKey(new URL(JWKS_URL), KeyUse.ENCRYPTION))
                    .thenReturn(createPublicJwk("test-enc-key"));

            var encKey = jwksCacheExtension.getOrGenerateJwksCacheItem();

            assertEquals("test-enc-key", encKey.getKeyId());
        }
    }

    public static JWK createPublicJwk(String keyId) {
        var keyPair = generateRsaKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .keyID(keyId)
                .build();
    }
}
