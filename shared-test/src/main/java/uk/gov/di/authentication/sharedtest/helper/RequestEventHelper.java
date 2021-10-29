package uk.gov.di.authentication.sharedtest.helper;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;

public class RequestEventHelper {

    public static ProxyRequestContext contextWithSourceIp(String ipAddress) {
        return new ProxyRequestContext().withIdentity(identityWithSourceIp(ipAddress));
    }

    public static RequestIdentity identityWithSourceIp(String ipAddress) {
        return new RequestIdentity().withSourceIp(ipAddress);
    }
}
