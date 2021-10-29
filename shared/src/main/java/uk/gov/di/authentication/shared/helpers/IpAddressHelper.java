package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static java.util.Collections.emptyMap;

public class IpAddressHelper {

    private static final Logger LOG = LoggerFactory.getLogger(IpAddressHelper.class);

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        var headers =
                Optional.ofNullable(input)
                        .map(APIGatewayProxyRequestEvent::getHeaders)
                        .orElse(emptyMap());

        LOG.info("Headers on request: {}", headers.keySet());

        if (headers.containsKey("x-forwarded-for")) {
            return headers.get("x-forwarded-for").split(",")[0].trim();
        }

        return Optional.ofNullable(input)
                .map(APIGatewayProxyRequestEvent::getRequestContext)
                .map(ProxyRequestContext::getIdentity)
                .map(RequestIdentity::getSourceIp)
                .orElse(AuditService.UNKNOWN);
    }
}
