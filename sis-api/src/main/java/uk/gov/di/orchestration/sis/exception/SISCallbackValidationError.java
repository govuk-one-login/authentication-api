package uk.gov.di.orchestration.sis.exception;

public record SISCallbackValidationError(
        String errorCode,
        String errorDescription,
        boolean userShouldRouteToIpv,
        boolean userRequestedUpdate) {

    public SISCallbackValidationError(String errorCode, String errorDescription) {
        this(errorCode, errorDescription, false, false);
    }
}
