package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.crac.Core;
import org.crac.Resource;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class StorageTokenJwkHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>,
                Resource {

    private final JwksService jwksService;
    private static final Logger LOG = LogManager.getLogger(StorageTokenJwkHandler.class);

    public StorageTokenJwkHandler(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    public StorageTokenJwkHandler(ConfigurationService configurationService) {
        this.jwksService =
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService));
    }

    public StorageTokenJwkHandler() {
        this(ConfigurationService.getInstance());
        Core.getGlobalContext().register(this);
    }

    @Override
    public void beforeCheckpoint(org.crac.Context<? extends Resource> context) throws Exception {
        LOG.info("Executing before checkpoint");
        this.storageTokenJwkRequestHandler();
        // Empty key cache, so we can force the key to be re-fetched everytime
        // the SnapStart image is restored. This allows us to fetch the key
        // on every restore, but continue to cache it for the duration that
        // the same lambda exists.
        this.jwksService.emptyCache();
    }

    @Override
    public void afterRestore(org.crac.Context<? extends Resource> context) throws Exception {}

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), this::storageTokenJwkRequestHandler);
    }

    public APIGatewayProxyResponseEvent storageTokenJwkRequestHandler() {
        try {
            LOG.info("StorageTokenJwk request received");

            List<JWK> signingKeys = new ArrayList<>();

            signingKeys.add(jwksService.getPublicStorageTokenJwkWithOpaqueId());

            JWKSet jwkSet = new JWKSet(signingKeys);

            LOG.info("Generating StorageTokenJwk successful response");

            return generateApiGatewayProxyResponse(
                    200,
                    segmentedFunctionCall("serialiseJWKSet", () -> jwkSet.toString(true)),
                    Map.of("Cache-Control", "max-age=86400"),
                    null);
        } catch (Exception e) {
            LOG.error("Error in StorageTokenJwk lambda", e);
            return generateApiGatewayProxyResponse(500, "Error providing StorageTokenJwk data");
        }
    }
}
