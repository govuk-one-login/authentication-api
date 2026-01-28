package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public class AMCFailureAntiCorruption {

    private AMCFailureAntiCorruption() {}

    public static ErrorResponseWithStatus toHttpResponse(AMCAuthorizeFailureReason failureReason) {
        return switch (failureReason) {
            case JWT_ENCODING_ERROR -> new ErrorResponseWithStatus(
                    400, ErrorResponse.AMC_JWT_ENCODING_ERROR);
            case TRANSCODING_ERROR -> new ErrorResponseWithStatus(
                    400, ErrorResponse.AMC_TRANSCODING_ERROR);
            case SIGNING_ERROR -> new ErrorResponseWithStatus(500, ErrorResponse.AMC_SIGNING_ERROR);
            case ENCRYPTION_ERROR -> new ErrorResponseWithStatus(
                    500, ErrorResponse.AMC_ENCRYPTION_ERROR);
            case UNKNOWN_JWT_SIGNING_ERROR -> new ErrorResponseWithStatus(
                    500, ErrorResponse.AMC_UNKNOWN_JWT_SIGNING_ERROR);
            case UNKNOWN_JWT_ENCRYPTING_ERROR -> new ErrorResponseWithStatus(
                    500, ErrorResponse.AMC_UNKNOWN_JWT_ENCRYPTING_ERROR);
        };
    }

    public static APIGatewayProxyResponseEvent toApiGatewayProxyErrorResponse(
            AMCAuthorizeFailureReason failureReason) {
        var httpResponse = toHttpResponse(failureReason);
        return generateApiGatewayProxyErrorResponse(
                httpResponse.statusCode(), httpResponse.errorResponse());
    }
}
