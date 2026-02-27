package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysCreateHandlerFailureReason {
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey"),
    PASSKEY_EXISTS("passkey_exists"),
    INVALID_AAGUID("invalid_aaguid"),
    REQUEST_MISSING_PARAMS("request_missing_params");

    private final String value;

    PasskeysCreateHandlerFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
