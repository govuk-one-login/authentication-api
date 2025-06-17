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
    ERROR_1006(1006, "Password must be at least 8 characters and not longer than 256 characters"),
    ERROR_1007(1007, "Password must contain a number, but not contain only numbers"),
    ERROR_1008(1008, "Invalid login credentials"),
    ERROR_1009(1009, "An account with this email address already exists"),
    ERROR_1010(1010, "An account with this email address does not exist"),
    ERROR_1011(1011, "Phone number is missing"),
    INVALID_PHONE_NUMBER(1012, "Phone number is invalid"),
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
    ERROR_1043(1043, "User entered invalid authenticator app code"),
    NEW_PHONE_NUMBER_ALREADY_IN_USE(1044, "New phone number is the same as current phone number"),
    ERROR_1045(1045, "User account is temporarily locked from sign in"),
    ERROR_1046(
            1046,
            "System has sent too many email verification codes for changing how to receive security codes"),
    ERROR_1047(
            1047,
            "System is blocked from sending any email verification codes for changing how to receive security codes"),
    ERROR_1048(
            1048,
            "User entered invalid email verification code for changing how to receive security codes too many times"),
    ERROR_1049(1049, "Email from session does not have a user profile"),
    ERROR_1050(1050, "Authorization Auth Code not enabled"),
    ERROR_1051(1051, "Account Interventions API throttled"),
    ERROR_1052(1052, "Account Interventions API response Server Error"),
    ERROR_1053(1053, "Account Interventions API Bad Gateway"),
    ERROR_1054(1054, "Account Interventions API Gateway Timeout"),
    ERROR_1055(1055, "Account Interventions API Unexpected Error"),
    ERROR_1056(1056, "User not found or no match"),
    ERROR_1057(1057, "User entered invalid reauth sign in details too many times"),
    ERROR_1058(1058, "IPV TokenResponse was not successful"),
    ERROR_1059(1059, "Error getting reverification result"),
    ERROR_1060(1060, "Failed to generate MFA Reset Authorize JAR for IPV"),
    ERROR_1061(1061, "State returned from IPV does not match expected state"),
    ERROR_1062(1062, "Invalid MFAMethod"),
    ERROR_1063(1063, "New method management api not available in environment"),
    ERROR_1064(1064, "Error retrieving mfa methods"),
    ERROR_1065(1065, "Mfa method not found"),
    ERROR_1066(1066, "Cannot delete default priority mfa method"),
    ERROR_1067(1067, "Cannot delete mfa method for non-migrated user"),
    ERROR_1068(1068, "MFA method count limit reached"),
    ERROR_1069(1069, "SMS MFA with same number already exists"),
    ERROR_1070(1070, "AUTH APP MFA already exists"),
    ERROR_1071(1071, "Account Management API encountered Unexpected Error"),
    ERROR_1072(1072, "Cannot change type of mfa method"),
    ERROR_1073(1073, "Cannot change priority of default mfa method"),
    ERROR_1074(1074, "Cannot update primary sms number to number already in use by backup"),
    ERROR_1075(1075, "Cannot update a backup sms mfa method's phone number"),
    ERROR_1076(1076, "Cannot update a backup sms mfa method's auth app credential"),
    ERROR_1077(1077, "Cannot edit a backup mfa method"),
    ERROR_1078(1078, "Unexpected error creating mfa identifier for auth app mfa method"),
    ERROR_1079(1079, "Invalid principal in request"),
    ERROR_1080(1080, "Default method already exists, new one cannot be created."),
    ERROR_1081(1081, "Attempting to validate auth app code for user without auth app method"),
    ERROR_1082(1082, "Cannot add a second auth app."),
    ERROR_1083(1083, "User's account is suspended"),
    ERROR_1084(1084, "User's account is blocked"),
    NO_USER_PROFILE_FOR_EMAIL(1085, "Email from request does not have a user profile"),
    USER_DOES_NOT_HAVE_ACCOUNT(1086, "Email from request does not have any user credentials"),
    ERROR_1087(1087, "Unsupported notification identifier in request");

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
