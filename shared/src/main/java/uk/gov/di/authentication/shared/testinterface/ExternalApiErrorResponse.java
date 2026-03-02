package uk.gov.di.authentication.shared.testinterface;

public enum ExternalApiErrorResponse implements ErrorResponse {
    SESSION_ID_MISSING(1000, "Session-Id is missing or invalid"),
    REQUEST_MISSING_PARAMS(1001, "Request is missing parameters"),
    SERIALIZATION_ERROR(1097, "Failed to serialize API Gateway proxy response"),
    AMC_JWT_ENCODING_ERROR(1200, "Failed to encode JWT for AMC authorization"),
    AMC_TRANSCODING_ERROR(1201, "Failed to transcode data for AMC authorization"),
    AMC_SIGNING_ERROR(1202, "Failed to sign JWT for AMC authorization"),
    AMC_ENCRYPTION_ERROR(1203, "Failed to encrypt JWT for AMC authorization"),
    AMC_UNKNOWN_JWT_SIGNING_ERROR(1204, "Unknown error signing JWT for AMC authorization"),
    AMC_UNKNOWN_JWT_ENCRYPTING_ERROR(1205, "Unknown error encrypting JWT for AMC authorization"),
    AMC_TOKEN_RESPONSE_ERROR(1206, "Failed to get token from AMC authorization"),
    AMC_TOKEN_UNEXPECTED_ERROR(1207, "Unexpected error calling AMC token"),
    AMC_JOURNEY_OUTCOME_RESPONSE_ERROR(
            1208, "Failed to get journey outcome from AMC authorization"),
    AMC_JOURNEY_OUTCOME_UNEXPECTED_ERROR(1209, "Unexpected error calling AMC journey outcome");

    private int code;
    private String message;

    ExternalApiErrorResponse(int code, String message) {
        this.code = code;
        this.message = message;
    }

    @Override
    public int getCode() {
        return this.code;
    }

    @Override
    public String getMessage() {
        return this.message;
    }
}
