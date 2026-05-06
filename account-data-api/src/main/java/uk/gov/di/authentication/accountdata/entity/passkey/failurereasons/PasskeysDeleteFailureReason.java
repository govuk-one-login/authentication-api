package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysDeleteFailureReason {
    PASSKEY_NOT_FOUND("passkey_not_found");

    private final String value;

    PasskeysDeleteFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
