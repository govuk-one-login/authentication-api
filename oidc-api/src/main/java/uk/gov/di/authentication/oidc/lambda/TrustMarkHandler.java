package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.helpers.ApiResponse;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.Arrays;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class TrustMarkHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final OidcAPI oidcApi;
    private static final Logger LOG = LogManager.getLogger(TrustMarkHandler.class);

    public TrustMarkHandler(OidcAPI oidcApi) {
        this.oidcApi = oidcApi;
    }

    public TrustMarkHandler() {
        this(new OidcAPI(ConfigurationService.getInstance()));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("TrustMark request received");

        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());

        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), this::trustmarkRequestHandler);
    }

    public APIGatewayProxyResponseEvent trustmarkRequestHandler() {
        return ApiResponse.ok(createTrustMarkResponse());
    }

    private TrustMarkResponse createTrustMarkResponse() {
        return new TrustMarkResponse(
                oidcApi.baseURI().toString(),
                oidcApi.baseURI().toString(),
                Arrays.asList(
                        CredentialTrustLevel.LOW_LEVEL.getValue(),
                        CredentialTrustLevel.MEDIUM_LEVEL.getValue()),
                LevelOfConfidence.getAllSupportedLevelOfConfidenceValues());
    }
}
