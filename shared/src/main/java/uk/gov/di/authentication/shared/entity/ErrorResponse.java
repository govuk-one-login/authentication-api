package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.JsonAdapter;
import uk.gov.di.authentication.shared.serialization.ErrorResponseAdapter;

@JsonAdapter(ErrorResponseAdapter.class)
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
    ERROR_1021(1021, "User entered invalid password reset code"),
    ERROR_1022(1022, "User has requested too many password resets"),
    ERROR_1023(1023, "User cannot request another password reset"),
    ERROR_1024(1024, "New password cannot be the same as current password"),
    ERROR_1025(1025, "User has sent too many MFA OTP codes"),
    ERROR_1026(1026, "User is blocked from sending any MFA OTP codes"),
    ERROR_1027(1027, "User has entered invalid mfa code too many times"),
    ERROR_1028(1028, "User has entered the incorrect password too many times"),
    ERROR_1029(1029, "System has sent too many email verifications codes"),
    ERROR_1030(1030, "System has sent too many phone verifications codes"),
    ERROR_1031(1031, "System is blocked from sending any email verifications codes"),
    ERROR_1032(1032, "System is blocked from sending any phone verifications codes"),
    ERROR_1033(1033, "User entered invalid email verification code too many times"),
    ERROR_1034(1034, "User entered invalid phone verification code too many times"),
    ERROR_1035(1035, "User entered invalid mfa code"),
    ERROR_1036(1036, "User entered invalid email verification code"),
    ERROR_1037(1037, "User entered invalid phone verification code"),
    ERROR_1038(1038, "Invalid Authentication Request"),
    ERROR_1039(1039, "User entered invalid password reset code too many times"),
    ERROR_1040(1040, "Password is too common"),
    ERROR_1041(1041, "Auth app secret is invalid"),
    ERROR_1042(1042, "User entered invalid authenticator app verification code too many times"),
    ERROR_1043(1043, "User entered invalid authenticator app code");

    private int code;

    private String message;

    ErrorResponse(int code, String message) {
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
