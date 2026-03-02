package uk.gov.di.authentication.shared.testinterface;

public enum AccountDataErrorResponse implements ErrorResponse {
    PASSKEY_ALREADY_EXISTS(1093, "Passkey already exists"),
    INVALID_AAGUID(1094, "Invalid AAGUID format"),
    INVALID_CREDENTIAL(1095, "Invalid credential format"),
    SERIALIZATION_ERROR(1097, "Failed to serialize API Gateway proxy response");

    private int code;
    private String message;

    AccountDataErrorResponse(int code, String message) {
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
