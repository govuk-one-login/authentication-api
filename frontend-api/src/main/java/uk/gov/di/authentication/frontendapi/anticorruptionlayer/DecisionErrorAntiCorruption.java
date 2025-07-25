package uk.gov.di.authentication.frontendapi.anticorruptionlayer;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;

/**
 * Anti-corruption layer that translates DecisionError from the user-permissions domain into
 * ErrorResponse for the frontend API domain.
 *
 * <p>This prevents the frontend API from being corrupted by changes in the user-permissions
 * domain's error model and maintains clean domain boundaries.
 */
public class DecisionErrorAntiCorruption {

    /**
     * Converts a DecisionError from the user-permissions domain to an ErrorResponse suitable for
     * the frontend API.
     *
     * @param decisionError The error from the user-permissions domain
     * @return The corresponding ErrorResponse for the frontend API
     */
    public static ErrorResponse toErrorResponse(DecisionError decisionError) {
        return switch (decisionError) {
            case UNKNOWN, STORAGE_SERVICE_ERROR, CONFIGURATION_ERROR -> ErrorResponse
                    .ACCT_TEMPORARILY_LOCKED;
            case INVALID_USER_CONTEXT -> ErrorResponse.REQUEST_MISSING_PARAMS;
        };
    }
}
