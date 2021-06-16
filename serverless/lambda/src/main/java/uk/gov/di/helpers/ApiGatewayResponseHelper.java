package uk.gov.di.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

public class ApiGatewayResponseHelper {
    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);
        return apiGatewayProxyResponseEvent;
    }
}
