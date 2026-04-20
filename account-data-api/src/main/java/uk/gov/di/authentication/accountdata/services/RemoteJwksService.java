package uk.gov.di.authentication.accountdata.services;

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
import uk.gov.di.authentication.shared.entity.Result;

import java.net.URL;

import static java.lang.String.format;

public class RemoteJwksService {

    private static final Logger LOG = LogManager.getLogger(RemoteJwksService.class);
    private static final ResourceRetriever DEFAULT_RESOURCE_RETRIEVER =
            new DefaultResourceRetriever(25000, 25000);
    private final JWKSource<SecurityContext> jwkSource;
    private final URL url;

    public RemoteJwksService(URL url) {
        this(
                JWKSourceBuilder.create(url, DEFAULT_RESOURCE_RETRIEVER)
                        .retrying(true)
                        .refreshAheadCache(false)
                        .cache(true)
                        .rateLimited(false)
                        .build(),
                url);
    }

    public RemoteJwksService(JWKSource<SecurityContext> jwkSource, URL url) {
        this.jwkSource = jwkSource;
        this.url = url;
    }

    public Result<String, JWK> retrieveJwkFromURLWithKeyId(String keyId) {
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(keyId).build());

        LOG.info("Retrieving JWKSet from URL: {}", url);
        try {
            var maybeJwk = jwkSource.get(selector, null).stream().findFirst();
            return maybeJwk.<Result<String, JWK>>map(Result::success)
                    .orElseGet(() -> Result.failure("No JWK found with matching id"));
        } catch (KeySourceException e) {
            return Result.failure(format("Error retrieving jwks key %s", e.getMessage()));
        }
    }
}
