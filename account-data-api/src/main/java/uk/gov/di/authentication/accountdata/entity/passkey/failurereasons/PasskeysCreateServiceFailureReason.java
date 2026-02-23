package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysCreateServiceFailureReason {
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey"),
    PASSKEY_EXISTS("passkey_exists");

    private final String value;

    PasskeysCreateServiceFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
