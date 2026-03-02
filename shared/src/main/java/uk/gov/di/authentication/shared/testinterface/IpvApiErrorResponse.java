package uk.gov.di.authentication.shared.testinterface;

public enum IpvApiErrorResponse implements ErrorResponse {
    UNSUCCESSFUL_IPV_TOKEN_RESPONSE(1058, "IPV TokenResponse was not successful"),
    REVERIFICATION_RESULT_GET_ERROR(1059, "Error getting reverification result"),
    MFA_RESET_JAR_GENERATION_ERROR(1060, "Failed to generate MFA Reset Authorize JAR for IPV"),
    IPV_STATE_MISMATCH(1061, "State returned from IPV does not match expected state"),
    SERIALIZATION_ERROR(1097, "Failed to serialize API Gateway proxy response");

    private int code;
    private String message;

    IpvApiErrorResponse(int code, String message) {
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
