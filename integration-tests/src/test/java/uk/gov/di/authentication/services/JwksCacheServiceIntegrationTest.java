package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.sharedtest.extensions.JwksCacheExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwksCacheServiceIntegrationTest {
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();

    @RegisterExtension
    public static final JwksCacheExtension jwksCacheExtension = new JwksCacheExtension();

    @Test
    void shouldPutMultipleSigningKeys() {
        var key1 = new JwksCacheItem("http://example.com", "test-enc-key-1", VALID_TTL);
        var key2 = new JwksCacheItem("http://example.com", "test-enc-key-2", VALID_TTL);

        jwksCacheExtension.storeKey(key1);
        jwksCacheExtension.storeKey(key2);

        var encKey = jwksCacheExtension.getEncryptionKey("http://example.com");

        assertEquals("test-enc-key-1", encKey.get().getKeyId());
    }
}
