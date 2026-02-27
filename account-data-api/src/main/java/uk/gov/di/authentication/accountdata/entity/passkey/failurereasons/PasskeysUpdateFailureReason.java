package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysUpdateFailureReason {
    PARSING_PASSKEY_UPDATE_REQUEST_ERROR("parsing_passkey_update_request_error"),
    PASSKEY_NOT_FOUND("passkey_not_found"),
    FAILED_TO_UPDATE_PASSKEY("failed_to_update_passkey");

    private final String value;

    PasskeysUpdateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
