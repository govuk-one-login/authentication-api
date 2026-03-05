package uk.gov.di.authentication.accountdata.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;

public class RequestHelper {
    public static APIGatewayProxyRequestEvent.ProxyRequestContext contextWithSourceIp(
            String ipAddress) {
        var requestIdentity =
                new APIGatewayProxyRequestEvent.RequestIdentity().withSourceIp(ipAddress);
        return new APIGatewayProxyRequestEvent.ProxyRequestContext().withIdentity(requestIdentity);
    }
}
