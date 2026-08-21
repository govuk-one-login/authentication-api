package uk.gov.di.orchestration.sis.exception;

import uk.gov.di.orchestration.shared.oauth.CallbackValidationError;

public record SISCallbackValidationError(
        String code, String description, boolean userShouldRouteToIpv, boolean userRequestedUpdate)
        implements CallbackValidationError {

    public SISCallbackValidationError(String errorCode, String errorDescription) {
        this(errorCode, errorDescription, false, false);
    }
}
