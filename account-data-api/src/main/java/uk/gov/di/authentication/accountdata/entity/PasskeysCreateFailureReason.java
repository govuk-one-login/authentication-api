package uk.gov.di.authentication.accountdata.entity;

public enum PasskeysCreateFailureReason {
    PARSING_PASSKEY_CREATE_REQUEST_ERROR("parsing_passkey_create_request_error");

    private final String value;

    PasskeysCreateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
