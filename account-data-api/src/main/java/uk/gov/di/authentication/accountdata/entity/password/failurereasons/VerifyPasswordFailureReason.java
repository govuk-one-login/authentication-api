package uk.gov.di.authentication.accountdata.entity.password.failurereasons;

public enum VerifyPasswordFailureReason {
    FAILED_TO_SERIALIZE_RESPONSE("failed_to_serialize_response");

    private final String value;

    VerifyPasswordFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
