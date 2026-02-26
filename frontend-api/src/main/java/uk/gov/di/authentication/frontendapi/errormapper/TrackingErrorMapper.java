package uk.gov.di.authentication.frontendapi.errormapper;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

public class TrackingErrorMapper {

    private TrackingErrorMapper() {}

    public static ErrorResponse toErrorResponse(TrackingError trackingError) {
        return switch (trackingError) {
            case STORAGE_SERVICE_ERROR -> ErrorResponse.STORAGE_LAYER_ERROR;
        };
    }
}
