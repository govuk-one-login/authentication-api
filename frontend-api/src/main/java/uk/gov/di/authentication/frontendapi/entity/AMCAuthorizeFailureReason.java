package uk.gov.di.authentication.frontendapi.entity;

public enum AMCAuthorizeFailureReason {
    JWT_CONSTRUCTION_ERROR("jwt_construction_error"),
    TRANSCODING_ERROR("transcoding_error"),
    KMS_ERROR("kms_error");

    private final String value;

    AMCAuthorizeFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
