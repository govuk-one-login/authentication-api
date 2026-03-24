package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteProxyHandler.class);
    private final ConfigurationService configurationService;

    public PasskeysDeleteProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysDeleteProxyHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> passkeyDeleteProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeyDeleteProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysDeleteProxyHandler invoked");

        return generateApiGatewayProxyResponse(501, "Not implemented");
    }
}
