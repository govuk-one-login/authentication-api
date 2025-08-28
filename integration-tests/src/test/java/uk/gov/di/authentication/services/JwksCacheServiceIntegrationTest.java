package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.sharedtest.extensions.JwksCacheExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwksCacheServiceIntegrationTest {
    @RegisterExtension
    public static JwksCacheExtension jwksCacheExtension = new JwksCacheExtension();

    @Test
    void shouldPutMultipleSigningKeys() {
        var key1 = new JwksCacheItem("http://example.com", "test-enc-key-1", "enc");
        var key2 = new JwksCacheItem("http://example.com", "test-enc-key-2", "enc");
        var key3 = new JwksCacheItem("http://example.com", "test-sig-key-1", "sig");
        var key4 = new JwksCacheItem("http://example.com", "test-sig-key-2", "sig");

        jwksCacheExtension.storeKey(key1);
        jwksCacheExtension.storeKey(key2);
        jwksCacheExtension.storeKey(key3);
        jwksCacheExtension.storeKey(key4);

        var encKey = jwksCacheExtension.getEncryptionKey("http://example.com");
        var signingKeys = jwksCacheExtension.getSigningKeys("http://example.com");

        assertEquals("test-enc-key-1", encKey.get().getKeyId());
        assertEquals("test-sig-key-1", signingKeys.get(0).getKeyId());
        assertEquals("test-sig-key-2", signingKeys.get(1).getKeyId());
    }
}
