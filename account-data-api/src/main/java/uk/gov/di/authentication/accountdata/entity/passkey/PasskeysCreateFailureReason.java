package uk.gov.di.authentication.accountdata.entity.passkey;

public enum PasskeysCreateFailureReason {
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey"),
    PASSKEY_EXISTS("passkey_exists"),
    INVALID_AAGUID("invalid_aaguid");

    private final String value;

    PasskeysCreateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
