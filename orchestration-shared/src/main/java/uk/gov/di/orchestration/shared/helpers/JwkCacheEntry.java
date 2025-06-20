package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class JwkCacheEntry {
    private static final Logger LOG = LogManager.getLogger(JwkCacheEntry.class);
    private final URL jwksUrl;
    private final int expirationInSeconds;
    private final KeyUse keyUse;
    private final Set<Algorithm> algs;
    private JWK latestKey;
    private Date expireTime;

    private JwkCacheEntry(
            URL jwksUrl, int expirationInSeconds, KeyUse keyUse, Set<Algorithm> algs) {
        this.jwksUrl = jwksUrl;
        this.expirationInSeconds = expirationInSeconds;
        this.expireTime = NowHelper.nowPlus(this.expirationInSeconds, ChronoUnit.SECONDS);
        this.keyUse = keyUse;
        this.algs = algs;
        this.latestKey = getKeyFromUrl();
    }

    public static JwkCacheEntry forEncryptionKeys(URL url, int expirationInSeconds) {
        return forKeyUse(
                url, expirationInSeconds, KeyUse.ENCRYPTION, Set.of(JWEAlgorithm.RSA_OAEP_256));
    }

    public static JwkCacheEntry forKeyUse(
            URL url, int expirationInSeconds, KeyUse keyUse, Algorithm alg) {
        return new JwkCacheEntry(url, expirationInSeconds, keyUse, Set.of(alg));
    }

    public static JwkCacheEntry forKeyUse(
            URL url, int expirationInSeconds, KeyUse keyUse, Set<Algorithm> algs) {
        return new JwkCacheEntry(url, expirationInSeconds, keyUse, algs);
    }

    public JWK getKey() {
        if (NowHelper.now().after(expireTime)) {
            LOG.info("JWK Cache expired. Fetching latest key...");
            latestKey = getKeyFromUrl();
            expireTime = NowHelper.nowPlus(expirationInSeconds, ChronoUnit.SECONDS);
        }
        return latestKey;
    }

    private JWK getKeyFromUrl() {
        try {
            List<JWK> jwks = JwksUtils.retrieveJwksFromUrl(jwksUrl);
            LOG.info("Found {} {} JWKs at {}", jwks.size(), keyUse, jwksUrl);
            return jwks.stream()
                    .filter(key -> keyUse.equals(key.getKeyUse()))
                    .filter(key -> algs.contains(key.getAlgorithm()))
                    .findFirst()
                    .orElse(null);
        } catch (KeySourceException e) {
            throw new RuntimeException("Key sourcing failed", e);
        }
    }
}
