package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;

public class DecisionErrorAntiCorruption {

    private DecisionErrorAntiCorruption() {}

    public static ErrorResponse toErrorResponse(DecisionError decisionError) {
        return switch (decisionError) {
            case CONFIGURATION_ERROR -> ErrorResponse.ACCT_TEMPORARILY_LOCKED;
            case STORAGE_SERVICE_ERROR -> ErrorResponse.STORAGE_LAYER_ERROR;
            case INVALID_USER_CONTEXT -> ErrorResponse.REQUEST_MISSING_PARAMS;
        };
    }
}
