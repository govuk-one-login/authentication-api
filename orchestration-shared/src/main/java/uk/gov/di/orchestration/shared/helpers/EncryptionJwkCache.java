package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class EncryptionJwkCache {
    private static final Logger LOG = LogManager.getLogger(EncryptionJwkCache.class);
    private static final EncryptionJwkCache instance = new EncryptionJwkCache();
    private final Map<String, JwkCacheEntry> cacheEntryByUrl;

    private EncryptionJwkCache() {
        cacheEntryByUrl = new HashMap<>();
    }

    public static EncryptionJwkCache getInstance() {
        return instance;
    }

    public JwkCacheEntry getOrCreateEntry(URL url, int cacheExpiration) {
        JwkCacheEntry jwkCacheEntry;
        if (!cacheEntryByUrl.containsKey(url.toString())) {
            LOG.info(
                    "Cache entry does not exist for JWKS URL {}, creating new one with expiration of {} seconds",
                    url,
                    cacheExpiration);
            jwkCacheEntry = JwkCacheEntry.withUrlAndExpiration(url, cacheExpiration);
            cacheEntryByUrl.put(url.toString(), jwkCacheEntry);
        } else {
            LOG.info("Cache entry exists for JWKS URL {}", url);
            jwkCacheEntry = cacheEntryByUrl.get(url.toString());
        }
        return jwkCacheEntry;
    }

    public void clear() {
        cacheEntryByUrl.clear();
    }
}
