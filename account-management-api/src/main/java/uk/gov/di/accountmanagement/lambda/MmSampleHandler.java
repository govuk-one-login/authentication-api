package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class MmSampleHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MmSampleHandler.class);

    public MmSampleHandler() {}

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mmSampleRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent mmSampleRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("mm-sample request received");

        var pathParams = input.getPathParameters();
        if (pathParams != null && !pathParams.isEmpty()) {
            return handleWithPathParams(input, context);
        }

        return generateResponse(input, 200, "It worked!");
    }

    private APIGatewayProxyResponseEvent handleWithPathParams(
            APIGatewayProxyRequestEvent input, Context context) {
        var paramValue = input.getPathParameters().get("param");
        if (paramValue == null || paramValue.isEmpty()) {
            return generateResponse(
                    input, 400, "No path parameter set, but this endpoint requires one!");
        }

        return generateResponse(input, 200, "It worked! Param value: " + paramValue);
    }

    private APIGatewayProxyResponseEvent generateResponse(
            APIGatewayProxyRequestEvent input, int statusCode, String message) {
        LOG.info("Returning message: {}", message);
        String jsonString =
                new JSONObject()
                        .put("message", message)
                        .put("headers", input.getHeaders())
                        .put("body", input.getBody())
                        .put("method", input.getHttpMethod())
                        .toString(4);

        LOG.info("Sending response: {}", jsonString);
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        return new APIGatewayProxyResponseEvent()
                .withStatusCode(statusCode)
                .withBody(jsonString)
                .withHeaders(headers);
    }
}
