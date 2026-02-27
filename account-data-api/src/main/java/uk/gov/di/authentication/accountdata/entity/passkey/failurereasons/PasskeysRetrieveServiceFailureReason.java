package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysRetrieveServiceFailureReason {
    FAILED_TO_GET_PASSKEYS("failed_to_get_passkeys"),
    MISSING_SUBJECT_ID("missing_subject_id");

    private final String value;

    PasskeysRetrieveServiceFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
