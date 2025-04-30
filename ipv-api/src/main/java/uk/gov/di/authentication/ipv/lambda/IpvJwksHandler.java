package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IpvJwksHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final JwksService jwksService;
    private static final Logger LOG = LogManager.getLogger(IpvJwksHandler.class);

    public IpvJwksHandler(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    public IpvJwksHandler(ConfigurationService configurationService) {
        this.jwksService =
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService));
    }

    public IpvJwksHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), this::ipvJwksRequestHandler);
    }

    public APIGatewayProxyResponseEvent ipvJwksRequestHandler() {
        try {
            LOG.info("IpvJwks request received");

            List<JWK> signingKeys = new ArrayList<>();

            if (jwksService.isOrchIpvTokenSigningKeyPublishEnabled()) {
                signingKeys.add(jwksService.getPublicOrchIpvTokenJwkWithOpaqueId());
            }

            if (signingKeys.isEmpty()) {
                throw new RuntimeException(
                        "Feature flag misconfiguration - response must contain at least one signing key. Check at least one of AUTH_IPV_TOKEN_SIGNING_KEY_PUBLISH_ENABLED and ORCH_IPV_TOKEN_SIGNING_KEY_PUBLISH_ENABLED is true.");
            }

            JWKSet jwkSet = new JWKSet(signingKeys);

            LOG.info("Generating IpvJwks successful response");

            return generateApiGatewayProxyResponse(
                    200,
                    segmentedFunctionCall("serialiseJWKSet", () -> jwkSet.toString(true)),
                    Map.of("Cache-Control", "max-age=86400"),
                    null);
        } catch (Exception e) {
            LOG.error("Error in IpvJwks lambda", e);
            return generateApiGatewayProxyResponse(500, "Error providing IpvJwks data");
        }
    }
}
