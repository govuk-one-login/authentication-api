package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import java.util.function.Supplier;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ApiResponse {

    public static <T> APIGatewayProxyResponseEvent ok(Supplier<T> supplier) {
        try {
            return generateApiGatewayProxyResponse(200, supplier.get());
        } catch (Exception e) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }
}
