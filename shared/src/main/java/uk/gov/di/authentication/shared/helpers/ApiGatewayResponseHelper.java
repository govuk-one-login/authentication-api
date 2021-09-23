package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.util.List;
import java.util.Map;

public class ApiGatewayResponseHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayResponseHelper.class);

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, T body) throws JsonProcessingException {
        return generateApiGatewayProxyResponse(
                statusCode, new ObjectMapper().writeValueAsString(body));
    }

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        try {
            return generateApiGatewayProxyResponse(
                    statusCode, new ObjectMapper().writeValueAsString(errorResponse));
        } catch (JsonProcessingException e) {
            LOGGER.warn("Unable to generateApiGatewayProxyErrorResponse: " + e);
            return generateApiGatewayProxyResponse(500, "Internal server error");
        }
    }

    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body) {
        return generateApiGatewayProxyResponse(statusCode, body, null);
    }

    public static APIGatewayProxyResponseEvent generateEmptySuccessApiGatewayResponse() {
        return generateApiGatewayProxyResponse(204, "", null);
    }

    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body, Map<String, List<String>> multiValueHeaders) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);
        if (multiValueHeaders != null) {
            apiGatewayProxyResponseEvent.setMultiValueHeaders(multiValueHeaders);
        }
        return apiGatewayProxyResponseEvent;
    }
}
