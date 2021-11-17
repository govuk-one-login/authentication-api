package uk.gov.di.authentication.shared.entity;

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
    ERROR_1007(1007, "Password must contain a number"),
    ERROR_1008(1008, "Invalid login credentials"),
    ERROR_1009(1009, "An account with this email address already exists"),
    ERROR_1010(1010, "An account with this email address does not exist"),
    ERROR_1011(1011, "Phone number is missing"),
    ERROR_1012(1012, "Phone number is invalid"),
    ERROR_1013(1013, "Update profile type is invalid"),
    ERROR_1014(1014, "Phone number is not registered"),
    ERROR_1015(1015, "Client not found"),
    ERROR_1016(1016, "Invalid Redirect URI"),
    ERROR_1017(1017, "Invalid transition in user journey"),
    ERROR_1018(1018, "Client-Session-Id is missing or invalid"),
    ERROR_1019(1019, "Email addresses are the same"),
    ERROR_1020(1020, "Invalid OTP code"),
    ERROR_1021(1021, "Invalid Password reset code"),
    ERROR_1022(1022, "User has requested too many password resets"),
    ERROR_1023(1023, "User cannot request another password reset"),
    ERROR_1024(1024, "New password cannot be the same as current password");

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
