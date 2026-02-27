package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeyServiceUpdateFailureReason {
    PASSKEY_NOT_FOUND("passkey_not_found");

    private final String value;

    PasskeyServiceUpdateFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
