package uk.gov.di.authentication.frontendapi.errormapper;

import uk.gov.di.authentication.shared.testinterface.ErrorResponse;
import uk.gov.di.authentication.shared.testinterface.InternalApiErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;

public class DecisionErrorMapper {

    private DecisionErrorMapper() {}

    public static ErrorResponse toErrorResponse(DecisionError decisionError) {
        return switch (decisionError) {
            case CONFIGURATION_ERROR -> InternalApiErrorResponse.ACCT_TEMPORARILY_LOCKED;
            case STORAGE_SERVICE_ERROR -> InternalApiErrorResponse.STORAGE_LAYER_ERROR;
            case INVALID_USER_CONTEXT -> InternalApiErrorResponse.REQUEST_MISSING_PARAMS;
        };
    }
}
