package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class JwksHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final JwksService jwksService;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(JwksHandler.class);

    public JwksHandler(ConfigurationService configurationService, JwksService jwksService) {
        this.configurationService = configurationService;
        this.jwksService = jwksService;
    }

    public JwksHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.jwksService =
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService));
    }

    public JwksHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> jwksRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent jwksRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            LOG.info("JWKs request received");

            List<JWK> signingKeys = new ArrayList<>();

            signingKeys.add(jwksService.getPublicTokenJwkWithOpaqueId());
            signingKeys.add(jwksService.getPublicDocAppSigningJwkWithOpaqueId());

            if (configurationService.isRsaSigningAvailable()) {
                signingKeys.add(jwksService.getPublicTokenRsaJwkWithOpaqueId());
            }

            JWKSet jwkSet = new JWKSet(signingKeys);

            LOG.info("Generating JWKs successful response");

            return generateApiGatewayProxyResponse(
                    200,
                    segmentedFunctionCall("serialiseJWKSet", () -> jwkSet.toString(true)),
                    Map.of("Cache-Control", "max-age=86400"),
                    null);
        } catch (Exception e) {
            LOG.error("Error in JWKs lambda", e);
            return generateApiGatewayProxyResponse(500, "Error providing JWKs data");
        }
    }
}
