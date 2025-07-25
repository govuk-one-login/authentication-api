package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class JwkCacheEntryTest {
    private URL testJwksUrl;
    private static final JWK TEST_KEY_1 = mock(JWK.class);
    private static final JWK TEST_KEY_2 = mock(JWK.class);

    @BeforeEach
    void setup() throws Exception {
        testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
        when(TEST_KEY_1.getKeyUse()).thenReturn(KeyUse.ENCRYPTION);
        when(TEST_KEY_2.getKeyUse()).thenReturn(KeyUse.ENCRYPTION);
        when(TEST_KEY_1.getAlgorithm()).thenReturn(JWEAlgorithm.RSA_OAEP_256);
        when(TEST_KEY_2.getAlgorithm()).thenReturn(JWEAlgorithm.RSA_OAEP_256);
    }

    @Test
    void shouldCacheKeyOnCreation() {
        try (var mockJwksUtils = mockStatic(JwksUtils.class)) {
            mockJwksUtils
                    .when(() -> JwksUtils.getKey(testJwksUrl, KeyUse.ENCRYPTION))
                    .thenReturn(TEST_KEY_1);

            var cacheEntry = createCacheWithNoExpiration();
            assertEquals(TEST_KEY_1, cacheEntry.getKey());
        }
    }

    @Test
    void shouldStoreNullKeyIfNoKeysFoundAtUrl() {
        try (var mockJwksUtils = mockStatic(JwksUtils.class)) {
            mockJwksUtils
                    .when(() -> JwksUtils.getKey(testJwksUrl, KeyUse.ENCRYPTION))
                    .thenReturn(null);

            var cacheEntry = createCacheWithNoExpiration();
            assertNull(cacheEntry.getKey());
        }
    }

    @Test
    void shouldRefreshCacheIfExpirationHasPassed() {
        try (var mockJwksUtils = mockStatic(JwksUtils.class);
                var mockNowHelper = mockStatic(NowHelper.class)) {
            mockJwksUtils
                    .when(() -> JwksUtils.getKey(testJwksUrl, KeyUse.ENCRYPTION))
                    .thenReturn(TEST_KEY_1)
                    .thenReturn(TEST_KEY_2);
            mockNowHelper
                    .when(() -> NowHelper.nowPlus(300, ChronoUnit.SECONDS))
                    .thenReturn(
                            Date.from(Instant.parse("2025-01-20T09:05:00Z")),
                            Date.from(Instant.parse("2025-01-20T09:10:00Z")));
            mockNowHelper
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.parse("2025-01-20T09:06:00Z")));

            var cacheEntry = createCacheWithExpiration(300);
            // Cache expires on get, fetch keys again from URL
            assertEquals(TEST_KEY_2, cacheEntry.getKey());
        }
    }

    @Test
    void shouldNotRefreshCacheIfExpirationHasNotPassedYet() {
        try (var mockJwksUtils = mockStatic(JwksUtils.class);
                var mockNowHelper = mockStatic(NowHelper.class)) {
            mockJwksUtils
                    .when(() -> JwksUtils.getKey(testJwksUrl, KeyUse.ENCRYPTION))
                    .thenReturn(TEST_KEY_1)
                    .thenReturn(TEST_KEY_2);
            mockNowHelper
                    .when(() -> NowHelper.nowPlus(300, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.parse("2025-01-20T09:05:00Z")));
            mockNowHelper
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.parse("2025-01-20T09:03:00Z")));

            var cacheEntry = createCacheWithExpiration(300);
            assertEquals(TEST_KEY_1, cacheEntry.getKey());
        }
    }

    private JwkCacheEntry createCacheWithNoExpiration() {
        return createCacheWithExpiration(KeyUse.ENCRYPTION, Integer.MAX_VALUE);
    }

    private JwkCacheEntry createCacheWithExpiration(int expiration) {
        return createCacheWithExpiration(KeyUse.ENCRYPTION, expiration);
    }

    private JwkCacheEntry createCacheWithExpiration(KeyUse keyUse, int expiration) {
        return JwkCacheEntry.forKeyUse(testJwksUrl, expiration, keyUse);
    }
}
