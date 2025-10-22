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
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidOptionalHeader;

public class IpAddressHelper {
    private static final String CLOUD_FRONT_VIEWER_ADDRESS_HEADER_NAME =
            "Cloudfront-Viewer-Address";

    private static final Logger LOG = LogManager.getLogger(IpAddressHelper.class);

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        if (headersContainValidOptionalHeader(
                headers, CLOUD_FRONT_VIEWER_ADDRESS_HEADER_NAME, true)) {
            return getHeaderValueFromHeaders(headers, CLOUD_FRONT_VIEWER_ADDRESS_HEADER_NAME, true)
                    .split(":")[0]
                    .trim();
        } else if (headersContainValidOptionalHeader(headers, "X-Forwarded-For", true)) {
            return getHeaderValueFromHeaders(headers, "X-Forwarded-For", true).split(",")[0].trim();
        }

        LOG.warn(
                "No IP address present in cloudfront viewer or x-forwarded-for header, attempting to retrieve from request context");

        return Optional.ofNullable(input)
                .map(APIGatewayProxyRequestEvent::getRequestContext)
                .map(ProxyRequestContext::getIdentity)
                .map(RequestIdentity::getSourceIp)
                .orElse(AuditService.UNKNOWN);
    }
}
