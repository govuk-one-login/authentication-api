package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public class DecisionErrorHttpMapper {

    private DecisionErrorHttpMapper() {}

    public static ErrorResponseWithStatus toHttpResponse(DecisionError decisionError) {
        ErrorResponse errorResponse = DecisionErrorAntiCorruption.toErrorResponse(decisionError);
        int statusCode =
                switch (decisionError) {
                    case CONFIGURATION_ERROR -> 500;
                    case STORAGE_SERVICE_ERROR -> 500;
                    case INVALID_USER_CONTEXT -> 400;
                };
        return new ErrorResponseWithStatus(statusCode, errorResponse);
    }

    public static APIGatewayProxyResponseEvent toApiGatewayProxyErrorResponse(
            DecisionError decisionError) {
        var httpResponse = DecisionErrorHttpMapper.toHttpResponse(decisionError);
        return generateApiGatewayProxyErrorResponse(
                httpResponse.statusCode(), httpResponse.errorResponse());
    }
}
