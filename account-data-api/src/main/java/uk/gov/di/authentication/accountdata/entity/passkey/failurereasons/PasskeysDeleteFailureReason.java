package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysDeleteFailureReason {
    PASSKEY_NOT_FOUND("passkey_not_found"),
    FAILED_TO_DELETE_PASSKEY("failed_to_delete_passkey"),
    MISSING_SUBJECT_ID("missing_subject_id"),
    MISSING_PASSKEY_ID("missing_passkey_id"),
    UNAUTHORIZED_REQUEST("unauthorized_request");

    private final String value;

    PasskeysDeleteFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
