package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class JwksUtilsTest {
    private static final JWK TEST_KEY_1 = mock(JWK.class);
    private static final JWK TEST_KEY_2 = mock(JWK.class);

    @BeforeEach
    void setup() {
        when(TEST_KEY_1.getKeyUse()).thenReturn(KeyUse.ENCRYPTION);
        when(TEST_KEY_2.getKeyUse()).thenReturn(KeyUse.ENCRYPTION);
        when(TEST_KEY_1.getAlgorithm()).thenReturn(JWEAlgorithm.RSA_OAEP_256);
        when(TEST_KEY_2.getAlgorithm()).thenReturn(JWEAlgorithm.RSA_OAEP_256);
    }

    // QualityGateRegressionTest
    @Test
    void shouldCacheFirstKeyIfMultipleKeysArePresent() {
        var jwksKeys = List.of(TEST_KEY_1, TEST_KEY_2);
        var validKey = JwksUtils.getKey(jwksKeys, KeyUse.ENCRYPTION);
        assertEquals(TEST_KEY_1, validKey);
    }

    // QualityGateRegressionTest
    @Test
    void shouldIgnoreFirstKeyIfKeyHasDifferentUse() {
        when(TEST_KEY_1.getKeyUse()).thenReturn(KeyUse.SIGNATURE);
        var jwksKeys = List.of(TEST_KEY_1, TEST_KEY_2);
        var validKey = JwksUtils.getKey(jwksKeys, KeyUse.ENCRYPTION);
        assertEquals(TEST_KEY_2, validKey);
    }

    // QualityGateRegressionTest
    @Test
    void shouldIgnoreFirstKeyIfKeyHasDifferentAlg() {
        when(TEST_KEY_1.getAlgorithm()).thenReturn(JWEAlgorithm.ECDH_1PU);

        var jwksKeys = List.of(TEST_KEY_1, TEST_KEY_2);
        var validKey = JwksUtils.getKey(jwksKeys, KeyUse.ENCRYPTION);
        assertEquals(TEST_KEY_2, validKey);
    }

    // QualityGateRegressionTest
    @Test
    void shouldGetEncryptionKeyByKeyTypeIfKeyAlgIsNotPresent() {
        when(TEST_KEY_1.getAlgorithm()).thenReturn(null);
        when(TEST_KEY_1.getKeyType()).thenReturn(KeyType.RSA);
        when(TEST_KEY_2.getAlgorithm()).thenReturn(null);
        when(TEST_KEY_2.getKeyType()).thenReturn(KeyType.RSA);
        var jwksKeys = List.of(TEST_KEY_1, TEST_KEY_2);

        var validKey = JwksUtils.getKey(jwksKeys, KeyUse.ENCRYPTION);
        assertEquals(TEST_KEY_1, validKey);
    }
}
