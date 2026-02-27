package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum DynamoPasskeyServiceFailureReason {
    PASSKEY_EXISTS("passkey_exists"),
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey");

    private final String value;

    DynamoPasskeyServiceFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
