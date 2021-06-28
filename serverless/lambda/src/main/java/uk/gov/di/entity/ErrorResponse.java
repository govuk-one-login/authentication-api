package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum ErrorResponse {
    ERROR_1000(1000, "Session-Id is missing or invalid"),
    ERROR_1001(1001, "Request is missing parameters"),
    ERROR_1002(1002, "Notification type is invalid"),
    ERROR_1003(1003, "Email code provided does not match the code sent");

    @JsonProperty("code")
    private int code;

    @JsonProperty("message")
    private String message;

    ErrorResponse(
            @JsonProperty(required = true, value = "code") int code,
            @JsonProperty(required = true, value = "message") String message) {}

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
