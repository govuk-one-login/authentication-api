package uk.gov.di.authentication.frontendapi.entity;

public enum FinishPasskeyAssertionFailureReason {
    ASSERTION_FAILED_ERROR("assertion_failed_error");

    private final String value;

    FinishPasskeyAssertionFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
