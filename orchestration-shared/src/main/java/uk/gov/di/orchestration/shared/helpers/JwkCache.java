package uk.gov.di.orchestration.shared.helpers;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class JwkCache {
    private static final JwkCache instance = new JwkCache();
    private final Map<String, JwkCacheEntry> cacheEntryByUrl;

    private JwkCache() {
        cacheEntryByUrl = new HashMap<>();
    }

    public static JwkCache getInstance() {
        return instance;
    }

    public JwkCacheEntry getOrCreateEntry(URL url, int cacheTimeout) {
        JwkCacheEntry jwkCacheEntry;
        if (!cacheEntryByUrl.containsKey(url.toString())) {
            jwkCacheEntry = JwkCacheEntry.withUrlAndExpiration(url, cacheTimeout);
            cacheEntryByUrl.put(url.toString(), jwkCacheEntry);
        } else {
            jwkCacheEntry = cacheEntryByUrl.get(url.toString());
        }
        return jwkCacheEntry;
    }
}
