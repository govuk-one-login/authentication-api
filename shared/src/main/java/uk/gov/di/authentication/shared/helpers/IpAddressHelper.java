package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import uk.gov.di.authentication.shared.services.AuditService;

public class IpAddressHelper {

    public static String extractIpAddress(APIGatewayProxyRequestEvent input) {
        if (input.getHeaders() == null) {
            return AuditService.UNKNOWN;
        } else {
            return input.getHeaders().getOrDefault("x-forwarded-for", AuditService.UNKNOWN);
        }
    }
}
