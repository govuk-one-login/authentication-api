package uk.gov.di.authentication.ipv.entity;

public record IpvCallbackValidationError(
        String errorCode, String errorDescription, boolean isSessionInvalidation) {

    public IpvCallbackValidationError(String errorCode, String errorDescription) {
        this(errorCode, errorDescription, false);
    }
}
