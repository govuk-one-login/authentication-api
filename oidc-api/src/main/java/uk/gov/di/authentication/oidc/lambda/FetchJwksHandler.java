package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class FetchJwksHandler implements RequestHandler<Map<String, String>, String> {

    private final JwksService jwksService;

    public FetchJwksHandler(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    public FetchJwksHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.jwksService = new JwksService(configurationService, kmsConnectionService);
    }

    public FetchJwksHandler() {
        this(ConfigurationService.getInstance());
    }

    private static final Logger LOG = LogManager.getLogger(FetchJwksHandler.class);

    @Override
    public String handleRequest(Map<String, String> event, Context context) {
        attachTraceId();
        String url = event.get("url");
        String keyId = event.get("keyId");
        final String errorResponse = "error";
        try {
            if (url == null || keyId == null) {
                throw new IllegalArgumentException(
                        "FetchJwksHandler invoked with invalid argument(s)");
            }
            JWK jwk = jwksService.retrieveJwkFromURLWithKeyId(new URL(url), keyId);
            return jwk.toJSONString();
        } catch (KeySourceException e) {
            String errorMsg =
                    "Failed to fetch JWKS: could not find key in JWKS that matches provided keyId";
            LOG.error(errorMsg, e);
            return errorResponse;
        } catch (MalformedURLException e) {
            String errorMsg = "Failed to fetch JWKS: URL is malformed";
            LOG.error(errorMsg, e);
            return errorResponse;
        } catch (IllegalArgumentException e) {
            String errorMsg = "Failed to fetch JWKS: url and/or keyId parameter not present";
            LOG.error(errorMsg, e);
            return errorResponse;
        }
    }
}
