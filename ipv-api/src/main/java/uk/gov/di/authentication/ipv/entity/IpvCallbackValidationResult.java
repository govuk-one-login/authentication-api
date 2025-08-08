package uk.gov.di.authentication.ipv.entity;

public record IpvCallbackValidationResult(boolean isValid, FailureCode failureCode) {
    // TODO: Does this make sense?
    public static String GENERIC_CALLBACK_ERROR_DESCRIPTION =
            "Invalid authentication response received, a new authentication request may be successful";

    public IpvCallbackValidationResult(boolean isValid) {
        this(isValid, null);
    }

    public enum FailureCode {
        EMPTY_CALLBACK,
        OAUTH_ERROR,
        SESSION_INVALIDATION,
        MISSING_STATE,
        INVALID_STATE,
        MISSING_AUTH_CODE,
    }
}
