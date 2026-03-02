package uk.gov.di.authentication.shared.testinterface;

public enum ClientRegistryApiErrorResponse implements ErrorResponse {
    SESSION_ID_MISSING(1000, "Session-Id is missing or invalid"),
    REQUEST_MISSING_PARAMS(1001, "Request is missing parameters"),
    SERIALIZATION_ERROR(1097, "Failed to serialize API Gateway proxy response");

    private int code;
    private String message;

    ClientRegistryApiErrorResponse(int code, String message) {
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
