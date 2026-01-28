package uk.gov.di.authentication.frontendapi.entity;

public enum FinishPasskeyAssertionFailureReason {
    PARSING_ASSERTION_REQUEST_ERROR("parsing_assertion_request_error"),
    PARSING_PKC_ERROR("parsing_pkc_error"),
    ASSERTION_FAILED_ERROR("assertion_failed_error");

    private final String value;

    FinishPasskeyAssertionFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
