package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysCreateHandlerFailureReason {
    FAILED_TO_SAVE_PASSKEY("failed_to_save_passkey"),
    PASSKEY_EXISTS("passkey_exists"),
    INVALID_AAGUID("invalid_aaguid"),
    INVALID_REQUEST_BODY("invalid_request_body"),
    MISSING_SUBJECT_ID("missing_subject_id");

    private final String value;

    PasskeysCreateHandlerFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
