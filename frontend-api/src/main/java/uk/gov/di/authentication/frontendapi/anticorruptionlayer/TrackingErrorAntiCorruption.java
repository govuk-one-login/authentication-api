package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

public class TrackingErrorAntiCorruption {

    private TrackingErrorAntiCorruption() {}

    public static ErrorResponse toErrorResponse(TrackingError trackingError) {
        return switch (trackingError) {
            case STORAGE_SERVICE_ERROR -> ErrorResponse.STORAGE_LAYER_ERROR;
        };
    }
}
