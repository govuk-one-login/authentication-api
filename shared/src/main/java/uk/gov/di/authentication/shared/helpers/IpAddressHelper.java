package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static java.util.Collections.emptyMap;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class IpAddressHelper {

    private static String IP_HEADER_NAME = "X-Forwarded-For";

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        return getOptionalHeaderValueFromHeaders(headers, IP_HEADER_NAME, true)
                .map(forwardedValue -> forwardedValue.split(",")[0].trim())
                .orElse(
                        Optional.ofNullable(input)
                                .map(APIGatewayProxyRequestEvent::getRequestContext)
                                .map(ProxyRequestContext::getIdentity)
                                .map(RequestIdentity::getSourceIp)
                                .orElse(AuditService.UNKNOWN));
    }
}
