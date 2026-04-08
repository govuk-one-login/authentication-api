package uk.gov.di.authentication.frontendapi.entity.amc;

public enum TokenResponseError {
    ERROR_RESPONSE_FROM_TOKEN_REQUEST("Error response from token request"),
    IO_EXCEPTION("IO Exception"),
    PARSE_EXCEPTION("Parse Exception");

    private final String value;

    TokenResponseError(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
