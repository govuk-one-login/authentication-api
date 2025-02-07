package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URL;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

class EncryptionJwkCacheTest {
    private static final EncryptionJwkCache ENCRYPTION_JWK_CACHE = EncryptionJwkCache.getInstance();

    @BeforeEach
    void setup() {
        ENCRYPTION_JWK_CACHE.clear();
    }

    @Test
    void shouldCreateNewJwkCacheEntryIfNotFound() throws Exception {
        try (var mockJwkCacheEntry = mockStatic(JwkCacheEntry.class)) {
            URL testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
            int testExpiry = 123;

            ENCRYPTION_JWK_CACHE.getOrCreateEntry(testJwksUrl, testExpiry);
            mockJwkCacheEntry.verify(
                    () -> JwkCacheEntry.forEncryptionKeys(testJwksUrl, testExpiry));
        }
    }

    @Test
    void shouldUseExistingEntryIfPresent() throws Exception {
        try (var mockJwkCacheEntry = mockStatic(JwkCacheEntry.class)) {
            URL testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
            int testExpiry = 123;

            ENCRYPTION_JWK_CACHE.getOrCreateEntry(testJwksUrl, testExpiry);
            ENCRYPTION_JWK_CACHE.getOrCreateEntry(testJwksUrl, testExpiry);
            mockJwkCacheEntry.verify(
                    () -> JwkCacheEntry.forEncryptionKeys(testJwksUrl, testExpiry), times(1));
        }
    }
}
