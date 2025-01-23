package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URL;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

class JwkCacheTest {
    private static final JwkCache jwkCache = JwkCache.getInstance();

    @BeforeEach
    void setup() {
        jwkCache.clear();
    }

    @Test
    void shouldCreateNewJwkCacheEntryIfNotFound() throws Exception {
        try (var mockJwkCacheEntry = mockStatic(JwkCacheEntry.class)) {
            URL testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
            int testExpiry = 123;

            jwkCache.getOrCreateEntry(testJwksUrl, testExpiry);
            mockJwkCacheEntry.verify(
                    () -> JwkCacheEntry.withUrlAndExpiration(testJwksUrl, testExpiry));
        }
    }

    @Test
    void shouldUseExistingEntryIfPresent() throws Exception {
        try (var mockJwkCacheEntry = mockStatic(JwkCacheEntry.class)) {
            URL testJwksUrl = new URL("http://localhost/.well-known/jwks.json");
            int testExpiry = 123;

            jwkCache.getOrCreateEntry(testJwksUrl, testExpiry);
            jwkCache.getOrCreateEntry(testJwksUrl, testExpiry);
            mockJwkCacheEntry.verify(
                    () -> JwkCacheEntry.withUrlAndExpiration(testJwksUrl, testExpiry), times(1));
        }
    }
}
