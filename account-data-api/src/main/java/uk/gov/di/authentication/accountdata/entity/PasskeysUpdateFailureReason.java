package uk.gov.di.authentication.accountdata.entity;

public enum PasskeysUpdateFailureReason {
    PARSING_PASSKEY_UPDATE_REQUEST_ERROR("parsing_passkey_update_request_error");

    private final String value;

    PasskeysUpdateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
