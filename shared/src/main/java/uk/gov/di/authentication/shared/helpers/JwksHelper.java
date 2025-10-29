package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.net.URL;

import static com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT;

public class JwksHelper {
    public static JWKSource<SecurityContext> getJwkSource(ConfigurationService configurationService)
            throws MalformedURLException {
        boolean ipvJwksCallEnabled = configurationService.isIpvJwksCallEnabled();
        URL ipvJwksUrl = configurationService.getIpvJwksUrl();

        if (!ipvJwksCallEnabled) return null;
        if (ipvJwksUrl == null) return null;

        var jwkSourceBuilder =
                configurationService.isStubbedEnvironment()
                        ? JWKSourceBuilder.create(
                                ipvJwksUrl,
                                new DefaultResourceRetriever(3000, 3000, DEFAULT_HTTP_SIZE_LIMIT))
                        : JWKSourceBuilder.create(ipvJwksUrl);

        return jwkSourceBuilder
                .retrying(true)
                .refreshAheadCache(false)
                .cache(true)
                .rateLimited(false)
                .build();
    }
}
