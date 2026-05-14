package uk.gov.di.authentication.shared.entity;

public enum JwtFailureReason {
    JWT_ENCODING_ERROR("jwt_encoding_error"),
    UNKNOWN_JWT_SIGNING_ERROR("unknown_jwt_signing_error"),
    TRANSCODING_ERROR("transcoding_error"),
    SIGNING_ERROR("signing_error"),
    KEY_RETRIEVAL_ERROR("key_retrieval_error"),
    ENCRYPTION_ERROR("encryption_error"),
    UNKNOWN_JWT_ENCRYPTING_ERROR("unknown_jwt_encrypting_error"),
    JWKS_RETRIEVAL_ERROR("jwks_retrieval_error");

    private final String value;

    JwtFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
