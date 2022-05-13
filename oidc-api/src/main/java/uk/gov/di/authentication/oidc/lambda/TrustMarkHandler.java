package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class TrustMarkHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(TrustMarkHandler.class);

    public TrustMarkHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public TrustMarkHandler() {
        this.configurationService = ConfigurationService.getInstance();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> trustmarkRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent trustmarkRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                LOG.info("TrustMark request received");
                                return generateApiGatewayProxyResponse(
                                        200, createTrustMarkResponse());
                            } catch (JsonException | NoSuchElementException e) {
                                LOG.warn("Unable to generate TrustMark response", e);
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
                            }
                        });
    }

    private TrustMarkResponse createTrustMarkResponse() {
        return new TrustMarkResponse(
                configurationService.getOidcApiBaseURL().orElseThrow(),
                configurationService.getOidcApiBaseURL().orElseThrow(),
                Arrays.asList(
                        CredentialTrustLevel.LOW_LEVEL.getValue(),
                        CredentialTrustLevel.MEDIUM_LEVEL.getValue()),
                LevelOfConfidence.getAllSupportedLevelOfConfidenceValues());
    }
}
