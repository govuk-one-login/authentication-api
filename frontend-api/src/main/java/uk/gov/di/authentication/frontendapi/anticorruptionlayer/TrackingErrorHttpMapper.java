package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public class TrackingErrorHttpMapper {

    private TrackingErrorHttpMapper() {}

    public static ErrorResponseWithStatus toHttpResponse(TrackingError trackingError) {
        ErrorResponse errorResponse = TrackingErrorAntiCorruption.toErrorResponse(trackingError);
        int statusCode =
                switch (trackingError) {
                    case STORAGE_SERVICE_ERROR -> 500;
                };
        return new ErrorResponseWithStatus(statusCode, errorResponse);
    }

    public static APIGatewayProxyResponseEvent toApiGatewayProxyErrorResponse(
            TrackingError trackingError) {
        var httpResponse = TrackingErrorHttpMapper.toHttpResponse(trackingError);
        return generateApiGatewayProxyErrorResponse(
                httpResponse.statusCode(), httpResponse.errorResponse());
    }
}
