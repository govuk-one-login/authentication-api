package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URL;
import java.util.List;

public class JwksUtils {

    private static final Logger LOG = LogManager.getLogger(JwksUtils.class);
    private static final JWKMatcher ALL_KEYS = new JWKMatcher.Builder().build();

    private JwksUtils() {}

    public static JWK retrieveJwkFromURLWithKeyId(URL url, String keyId) throws KeySourceException {
        return retrieveJwkFromUrl(url, matcherForKeyId(keyId)).stream()
                .findFirst()
                .orElseThrow(
                        () -> new KeySourceException("No key found with given keyId: " + keyId));
    }

    public static List<JWK> retrieveJwksFromUrl(URL url) throws KeySourceException {
        return retrieveJwkFromUrl(url, ALL_KEYS);
    }

    private static List<JWK> retrieveJwkFromUrl(URL url, JWKMatcher jwkMatcher)
            throws KeySourceException {
        LOG.info("Retrieving JWKSet with URL: {}", url);
        JWKSelector selector = new JWKSelector(jwkMatcher);
        JWKSource<SecurityContext> jwkSource =
                JWKSourceBuilder.create(url)
                        .retrying(true)
                        .refreshAheadCache(false)
                        .cache(false)
                        .rateLimited(false)
                        .build();
        return jwkSource.get(selector, null);
    }

    private static JWKMatcher matcherForKeyId(String keyId) {
        return new JWKMatcher.Builder().keyID(keyId).build();
    }
}
