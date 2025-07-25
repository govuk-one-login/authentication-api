package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class JwkCacheEntry {
    private static final Logger LOG = LogManager.getLogger(JwkCacheEntry.class);
    private final URL jwksUrl;
    private final int expirationInSeconds;
    private final KeyUse keyUse;
    private JWK latestKey;
    private Date expireTime;

    private JwkCacheEntry(URL jwksUrl, int expirationInSeconds, KeyUse keyUse) {
        this.jwksUrl = jwksUrl;
        this.expirationInSeconds = expirationInSeconds;
        this.expireTime = NowHelper.nowPlus(this.expirationInSeconds, ChronoUnit.SECONDS);
        this.keyUse = keyUse;
        this.latestKey = JwksUtils.getKey(jwksUrl, keyUse);
    }

    public static JwkCacheEntry forEncryptionKeys(URL url, int expirationInSeconds) {
        return forKeyUse(url, expirationInSeconds, KeyUse.ENCRYPTION);
    }

    public static JwkCacheEntry forKeyUse(URL url, int expirationInSeconds, KeyUse keyUse) {
        return new JwkCacheEntry(url, expirationInSeconds, keyUse);
    }

    public JWK getKey() {
        if (NowHelper.now().after(expireTime)) {
            LOG.info("JWK Cache expired. Fetching latest key...");
            latestKey = JwksUtils.getKey(jwksUrl, keyUse);
            expireTime = NowHelper.nowPlus(expirationInSeconds, ChronoUnit.SECONDS);
        }
        return latestKey;
    }
}
