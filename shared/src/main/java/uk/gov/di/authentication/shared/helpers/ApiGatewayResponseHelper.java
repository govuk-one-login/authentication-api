package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class ApiGatewayResponseHelper {

    public enum SecurityHeaders {
        XSS_PROTECTION("X-XSS-Protection", "1; mode=block"),
        CONTENT_TYPE_OPTIONS("X-Content-Type-Options", "nosniff"),
        CONTENT_SECURITY_POLICY("Content-Security-Policy", "frame-ancestors 'none'"),
        STRICT_TRANSPORT_SECURITY(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
        FRAME_OPTIONS("X-Frame-Options", "DENY"),
        CACHE_CONTROL(HttpHeaders.CACHE_CONTROL, "no-cache, no-store"),
        PRAGMA(HttpHeaders.PRAGMA, "no-cache");

        private final String headerName;
        private final String headerValue;

        SecurityHeaders(String headerName, String headerValue) {
            this.headerName = headerName;
            this.headerValue = headerValue;
        }

        public static Map<String, String> headers() {
            return Arrays.stream(SecurityHeaders.values())
                    .collect(Collectors.toMap(x -> x.headerName, x -> x.headerValue));
        }
    }

    private static final Logger LOG = LogManager.getLogger(ApiGatewayResponseHelper.class);
    private static final Json objectMapper = SerializationService.getInstance();

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, T body) throws JsonException {
        return generateApiGatewayProxyResponse(statusCode, objectMapper.writeValueAsString(body));
    }

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {

        if (400 <= statusCode && statusCode <= 499) {
            LOG.warn(errorResponse.getMessage());
        } else {
            LOG.error(errorResponse.getMessage());
        }

        try {
            return generateApiGatewayProxyResponse(
                    statusCode, objectMapper.writeValueAsString(errorResponse));
        } catch (JsonException e) {
            LOG.warn("Unable to generateApiGatewayProxyErrorResponse: " + e);
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

        var response =
                new APIGatewayProxyResponseEvent()
                        .withStatusCode(statusCode)
                        .withBody(body)
                        .withHeaders(SecurityHeaders.headers());

        if (multiValueHeaders != null) {
            response.setMultiValueHeaders(multiValueHeaders);
        }

        return response;
    }

    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode,
            String body,
            Map<String, String> headers,
            Map<String, List<String>> multiValueHeaders) {

        var allHeaders = SecurityHeaders.headers();

        Optional.ofNullable(headers).ifPresent(allHeaders::putAll);

        var response =
                new APIGatewayProxyResponseEvent()
                        .withStatusCode(statusCode)
                        .withBody(body)
                        .withHeaders(allHeaders);

        if (multiValueHeaders != null) {
            response.setMultiValueHeaders(multiValueHeaders);
        }

        return response;
    }
}
