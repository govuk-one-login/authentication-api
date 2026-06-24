package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class SISJwksHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), this::sisJwksRequestHandler);
    }

    public APIGatewayProxyResponseEvent sisJwksRequestHandler() {
        return generateApiGatewayProxyResponse(
                200, "Test lambda", Map.of("Cache-Control", "max-age=86400"), null);
    }
}
