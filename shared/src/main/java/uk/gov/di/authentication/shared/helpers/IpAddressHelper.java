package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static java.util.Collections.emptyMap;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class IpAddressHelper {
    private static final Logger LOG = LogManager.getLogger(IpAddressHelper.class);

    private static String IP_HEADER_NAME = "X-Forwarded-For";

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        var maybeIpAddressFromHeaders =
                getOptionalHeaderValueFromHeaders(headers, IP_HEADER_NAME, true)
                        .map(IpAddressHelper::getFirstValueFromHeaderString);

        return maybeIpAddressFromHeaders.orElseGet(
                () -> {
                    LOG.warn(
                            "No IP address present in x-forwarded-for header, attempting to retrieve from request context");
                    return Optional.ofNullable(input)
                            .map(APIGatewayProxyRequestEvent::getRequestContext)
                            .map(ProxyRequestContext::getIdentity)
                            .map(RequestIdentity::getSourceIp)
                            .orElse(AuditService.UNKNOWN);
                });
    }

    private static String getFirstValueFromHeaderString(String headerString) {
        return headerString.split(",")[0].trim();
    }
}
