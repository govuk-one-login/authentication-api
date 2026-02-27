package uk.gov.di.authentication.accountdata.entity.passkey.failurereasons;

public enum PasskeysRetrieveHandlerFailureReasons {
    REQUEST_MISSING_PARAMS("request_missing_params"),
    FAILED_TO_GET_PASSKEYS("failed_to_get_passkeys"),
    FAILED_TO_SERIALIZE_RESPONSE("failed_to_serialize_response");

    private final String value;

    PasskeysRetrieveHandlerFailureReasons(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
