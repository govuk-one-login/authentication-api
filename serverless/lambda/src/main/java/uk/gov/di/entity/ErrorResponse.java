package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
    ERROR_1000(1000, "Session-Id is missing or invalid"),
    ERROR_1001(1001, "Request is missing parameters"),
    ERROR_1002(1002, "Notification type is invalid"),
    ERROR_1003(1003, "Email address is empty"),
    ERROR_1004(1004, "Email address is in an incorrect format"),
    ERROR_1005(1005, "Password is empty"),
    ERROR_1006(1006, "Password must be at least 8 characters"),
    ERROR_1007(1007, "Password must contain a number");

    @JsonProperty("code")
    private int code;

    @JsonProperty("message")
    private String message;

    ErrorResponse(
            @JsonProperty(required = true, value = "code") int code,
            @JsonProperty(required = true, value = "message") String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
