package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ApiResponse {

    public static <T> APIGatewayProxyResponseEvent ok(T supplier) {
        try {
            if (supplier instanceof AccessTokenResponse success) {
                return generateApiGatewayProxyResponse(200, success.toJSONObject().toJSONString());
            } else {
                return generateApiGatewayProxyResponse(200, supplier);
            }
        } catch (Exception e) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }

    public static <T> APIGatewayProxyResponseEvent badRequest(T supplier) {
        try {
            if (supplier instanceof ErrorObject error) {
                return generateApiGatewayProxyResponse(400, error.toJSONObject().toJSONString());
            } else {
                return generateApiGatewayProxyResponse(400, supplier);
            }
        } catch (Exception e) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
        }
    }
}
