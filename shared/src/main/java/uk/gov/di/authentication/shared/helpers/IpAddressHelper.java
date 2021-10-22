package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

public class IpAddressHelper {

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        return Optional.ofNullable(input)
                .map(APIGatewayProxyRequestEvent::getRequestContext)
                .map(ProxyRequestContext::getIdentity)
                .map(RequestIdentity::getSourceIp)
                .orElse(AuditService.UNKNOWN);
    }
}
