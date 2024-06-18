package uk.gov.di.authentication.frontendapi.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;

import java.util.Map;

import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;

public class ApiGatewayProxyRequestHelper {
    public static APIGatewayProxyRequestEvent apiRequestEventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(headers)
                .withBody(body)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
