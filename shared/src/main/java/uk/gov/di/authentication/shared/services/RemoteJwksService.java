package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URL;

public class RemoteJwksService {

    private static final Logger LOG = LogManager.getLogger(RemoteJwksService.class);
    private static final ResourceRetriever DEFAULT_RESOURCE_RETRIEVER =
            new DefaultResourceRetriever(25000, 25000);
    private final JWKSource<SecurityContext> jwkSource;
    private final URL url;

    public RemoteJwksService(URL url) {
        this.jwkSource =
                JWKSourceBuilder.create(url, DEFAULT_RESOURCE_RETRIEVER)
                        .retrying(true)
                        .refreshAheadCache(false)
                        .cache(true)
                        .rateLimited(false)
                        .build();
        this.url = url;
    }

    public JWK retrieveJwkFromURLWithKeyId(String keyId) throws KeySourceException {
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(keyId).build());

        LOG.info("Retrieving JWKSet from URL: {}", url);
        return jwkSource.get(selector, null).stream()
                .findFirst()
                .orElseThrow(() -> new KeySourceException("No key found with given keyID"));
    }
}
