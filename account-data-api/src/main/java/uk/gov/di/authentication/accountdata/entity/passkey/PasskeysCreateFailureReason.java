package uk.gov.di.authentication.accountdata.entity.passkey;

public enum PasskeysCreateFailureReason {
    PARSING_PASSKEY_CREATE_REQUEST_ERROR("parsing_passkey_create_request_error"),
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey"),
    PASSKEY_EXISTS("passkey_exists"),
    INVALID_AAGUID("invalid_aaguid"),
    INVALID_CREDENTIAL("invalid_credential");

    private final String value;

    PasskeysCreateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
