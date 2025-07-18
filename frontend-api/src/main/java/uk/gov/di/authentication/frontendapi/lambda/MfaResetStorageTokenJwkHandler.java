package uk.gov.di.authentication.frontendapi.lambda;

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
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class MfaResetStorageTokenJwkHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final JwksService jwksService;
    private static final Logger LOG = LogManager.getLogger(MfaResetStorageTokenJwkHandler.class);

    public MfaResetStorageTokenJwkHandler(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    public MfaResetStorageTokenJwkHandler(ConfigurationService configurationService) {
        this.jwksService =
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService));
    }

    public MfaResetStorageTokenJwkHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        return segmentedFunctionCall(
                "frontend-api::" + getClass().getSimpleName(),
                this::mfaResetStorageTokenJwkHandler);
    }

    public APIGatewayProxyResponseEvent mfaResetStorageTokenJwkHandler() {
        try {
            attachTraceId();
            LOG.info("Request for Auth MFA storage token signature verification key received.");

            List<JWK> signingKeys = new ArrayList<>();

            signingKeys.add(jwksService.getPublicMfaResetStorageTokenJwkWithOpaqueId());

            JWKSet jwkSet = new JWKSet(signingKeys);

            LOG.info("Served Auth MFA storage token signature verification key JWK set.");

            return generateApiGatewayProxyResponse(
                    200,
                    segmentedFunctionCall("serialiseJWKSet", () -> jwkSet.toString(true)),
                    Map.of("Cache-Control", "max-age=86400"),
                    null);
        } catch (Exception e) {
            LOG.error("Failed to serve Auth MFA storage token signature verification key.", e);
            return generateApiGatewayProxyResponse(
                    500, "Auth MFA storage token signature verification key not available.");
        }
    }
}
