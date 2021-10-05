package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.util.List;
import java.util.Map;

public class ApiGatewayResponseHelper {

    private static final String XSS_PROTECTION_HEADER_NAME = "X-XSS-Protection";
    private static final String CONTENT_TYPE_OPTIONS_HEADER_NAME = "X-Content-Type-Options";
    private static final String CONTENT_SECURITY_POLICY_HEADER_NAME = "Content-Security-Policy";
    private static final String STRICT_TRANSPORT_SECURITY_HEADER_NAME = "Strict-Transport-Security";
    private static final String X_FRAME_OPTIONS_HEADER_NAME = "X-Frame-Options";

    private static final String CACHE_CONTROL_HEADER_VALUE = "no-cache, no-store";
    private static final String PRAGMA_HEADER_VALUE = "no-cache";
    private static final String XSS_PROTECTION_HEADER_VALUE = "1; mode=block";
    private static final String CONTENT_TYPE_OPTIONS_HEADER_VALUE = "nosniff";
    private static final String CONTENT_SECURITY_POLICY_HEADER_VALUE = "frame-ancestors 'none'";
    private static final String STRICT_TRANSPORT_SECURITY_HEADER_VALUE =
            "max-age=31536000; includeSubDomains";
    private static final String X_FRAME_OPTIONS_HEADER_VALUE = "DENY";

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

        Map<String, String> securityHeaders =
                Map.ofEntries(
                        Map.entry(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_HEADER_VALUE),
                        Map.entry(HttpHeaders.PRAGMA, PRAGMA_HEADER_VALUE),
                        Map.entry(XSS_PROTECTION_HEADER_NAME, XSS_PROTECTION_HEADER_VALUE),
                        Map.entry(
                                CONTENT_TYPE_OPTIONS_HEADER_NAME,
                                CONTENT_TYPE_OPTIONS_HEADER_VALUE),
                        Map.entry(
                                CONTENT_SECURITY_POLICY_HEADER_NAME,
                                CONTENT_SECURITY_POLICY_HEADER_VALUE),
                        Map.entry(
                                STRICT_TRANSPORT_SECURITY_HEADER_NAME,
                                STRICT_TRANSPORT_SECURITY_HEADER_VALUE),
                        Map.entry(X_FRAME_OPTIONS_HEADER_NAME, X_FRAME_OPTIONS_HEADER_VALUE));
        apiGatewayProxyResponseEvent.setHeaders(securityHeaders);

        return apiGatewayProxyResponseEvent;
    }
}
