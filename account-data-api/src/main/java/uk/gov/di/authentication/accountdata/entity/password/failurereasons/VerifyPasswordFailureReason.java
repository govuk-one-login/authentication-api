package uk.gov.di.authentication.accountdata.entity.password.failurereasons;

public enum VerifyPasswordFailureReason {
    INVALID_REQUEST_BODY("invalid_request_body"),
    MISSING_SUBJECT_ID("missing_subject_id"),
    UNAUTHORIZED_REQUEST("unauthorized_request"),
    FAILED_TO_SERIALIZE_RESPONSE("failed_to_serialize_response");

    private final String value;

    VerifyPasswordFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
