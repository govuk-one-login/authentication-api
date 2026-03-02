package uk.gov.di.authentication.frontendapi.errormapper;

import uk.gov.di.authentication.shared.testinterface.InternalApiErrorResponse;
import uk.gov.di.authentication.shared.testinterface.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

public class TrackingErrorMapper {

    private TrackingErrorMapper() {}

    public static ErrorResponse toErrorResponse(TrackingError trackingError) {
        return switch (trackingError) {
            case STORAGE_SERVICE_ERROR -> InternalApiErrorResponse.STORAGE_LAYER_ERROR;
        };
    }
}
