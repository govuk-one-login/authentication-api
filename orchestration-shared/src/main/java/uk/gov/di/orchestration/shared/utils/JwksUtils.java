package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class JwksUtils {

    private static final Logger LOG = LogManager.getLogger(JwksUtils.class);
    private static final JWKMatcher ALL_KEYS = new JWKMatcher.Builder().build();
    private static final Map<KeyUse, KeyType> KEY_TYPE_BY_KEY_USE =
            Map.of(KeyUse.ENCRYPTION, KeyType.RSA);
    private static final Map<KeyUse, Set<Algorithm>> ALGS_BY_KEY_USE =
            Map.of(KeyUse.ENCRYPTION, Set.of(JWEAlgorithm.RSA_OAEP_256));

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

    public static JWK getKey(URL jwksUrl, KeyUse keyUse) {
        try {
            return getKey(retrieveJwksFromUrl(jwksUrl), keyUse);
        } catch (KeySourceException e) {
            throw new RuntimeException("Failed to source keys");
        }
    }

    public static JWK getKey(List<JWK> jwks, KeyUse keyUse) {
        var algs = ALGS_BY_KEY_USE.get(keyUse);
        var kty = KEY_TYPE_BY_KEY_USE.get(keyUse);

        LOG.info("Found {} {} JWKs", jwks.size(), keyUse);
        return getFirstKeyByAlg(jwks, keyUse, algs)
                .orElseGet(
                        () -> {
                            LOG.info("Cannot find key by alg. Falling back to finding key by kty");
                            return getFirstKeyByKty(jwks, keyUse, kty).orElse(null);
                        });
    }

    private static Optional<JWK> getFirstKeyByAlg(
            List<JWK> jwks, KeyUse keyUse, Set<Algorithm> algs) {
        return jwks.stream()
                .filter(key -> keyUse.equals(key.getKeyUse()))
                .filter(key -> key.getAlgorithm() != null && algs.contains(key.getAlgorithm()))
                .findFirst();
    }

    private static Optional<JWK> getFirstKeyByKty(List<JWK> jwks, KeyUse keyUse, KeyType kty) {
        return jwks.stream()
                .filter(key -> keyUse.equals(key.getKeyUse()))
                .filter(key -> kty.equals(key.getKeyType()))
                .findFirst();
    }
}
