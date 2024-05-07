package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static java.util.Collections.emptyMap;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class IpAddressHelper {

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        return getOptionalHeaderValueFromHeaders(headers, "X-Forwarded-For", true)
                .map(forwardedValue -> forwardedValue.split(",")[0].trim())
                .orElse(
                        Optional.ofNullable(input)
                                .map(APIGatewayProxyRequestEvent::getRequestContext)
                                .map(ProxyRequestContext::getIdentity)
                                .map(RequestIdentity::getSourceIp)
                                .orElse(AuditService.UNKNOWN));
    }
}
