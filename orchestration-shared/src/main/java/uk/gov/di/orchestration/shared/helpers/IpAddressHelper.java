package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.AuditService;

import java.util.Optional;

import static java.util.Collections.emptyMap;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class IpAddressHelper {
    private static final String cloudFrontViewerAddressHeaderName = "Cloudfront-Viewer-Address";

    private static final Logger LOG = LogManager.getLogger(IpAddressHelper.class);

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        if (headersContainValidHeader(headers, cloudFrontViewerAddressHeaderName, true)) {
            return getHeaderValueFromHeaders(headers, cloudFrontViewerAddressHeaderName, true)
                    .split(":")[0]
                    .trim();
        } else if (headersContainValidHeader(headers, "X-Forwarded-For", true)) {
            return getHeaderValueFromHeaders(headers, "X-Forwarded-For", true).split(",")[0].trim();
        }

        LOG.warn(
                "No IP address present in x-forwarded-for header, attempting to retrieve from request context");

        return Optional.ofNullable(input)
                .map(APIGatewayProxyRequestEvent::getRequestContext)
                .map(ProxyRequestContext::getIdentity)
                .map(RequestIdentity::getSourceIp)
                .orElse(AuditService.UNKNOWN);
    }
}
