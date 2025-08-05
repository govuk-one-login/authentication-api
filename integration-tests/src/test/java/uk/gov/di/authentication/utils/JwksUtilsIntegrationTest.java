package uk.gov.di.authentication.utils;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.utils.JwksUtils;
import uk.gov.di.orchestration.sharedtest.extensions.JwksExtension;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class JwksUtilsIntegrationTest {
    @RegisterExtension private static final JwksExtension jwksExtension = new JwksExtension();
    private static final String TEST_JWK_ID_1 = "test-jwk-id-1";
    private static final String TEST_JWK_ID_2 = "test-jwk-id-2";
    private static final JWK TEST_JWK_1 = createPublicJwk(TEST_JWK_ID_1);
    private static final JWK TEST_JWK_2 = createPublicJwk(TEST_JWK_ID_2);

    @BeforeAll
    static void setup() {
        jwksExtension.init(new JWKSet(List.of(TEST_JWK_1, TEST_JWK_2)));
    }

    @Test
    void shouldRetrieveSpecificKeyFromJwksEndpoint() throws Exception {
        var actualKey =
                JwksUtils.retrieveJwkFromURLWithKeyId(jwksExtension.getJwksUrl(), TEST_JWK_ID_1);

        assertEquals(TEST_JWK_1, actualKey);
    }

    @Test
    void shouldThrowIfSpecificKeyNotFoundOnJwksEndpoint() {
        assertThrows(
                KeySourceException.class,
                () ->
                        JwksUtils.retrieveJwkFromURLWithKeyId(
                                jwksExtension.getJwksUrl(), "not-a-key-id"));
    }

    @Test
    void shouldRetrieveListOfKeysFromJwksEndpoint() throws Exception {
        var actualKeys = JwksUtils.retrieveJwksFromUrl(jwksExtension.getJwksUrl());

        assertEquals(List.of(TEST_JWK_1, TEST_JWK_2), actualKeys);
    }

    @Test
    void shouldGetFirstKeyOfTypeFromJwksEndpoint() throws Exception {
        var actualKey = JwksUtils.getKey(jwksExtension.getJwksUrl(), KeyUse.ENCRYPTION);

        assertEquals(TEST_JWK_1, actualKey);
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
