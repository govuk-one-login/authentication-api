package uk.gov.di.authentication.frontendapi.entity.amc;

public enum AMCFailureReason {
    JWT_ENCODING_ERROR("jwt_encoding_error"),
    UNKNOWN_JWT_SIGNING_ERROR("unknown_jwt_signing_error"),
    TRANSCODING_ERROR("transcoding_error"),
    SIGNING_ERROR("signing_error"),
    ENCRYPTION_ERROR("encryption_error"),
    UNKNOWN_JWT_ENCRYPTING_ERROR("unknown_jwt_encrypting_error"),
    JWKS_RETRIEVAL_ERROR("jwks_retrieval_error");

    private final String value;

    AMCFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
