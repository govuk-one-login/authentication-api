package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.JsonAdapter;
import uk.gov.di.authentication.shared.serialization.ErrorResponseAdapter;

@JsonAdapter(ErrorResponseAdapter.class)
public enum ErrorResponse {
    SESSION_ID_MISSING(1000, "Session-Id is missing or invalid"),
    REQUEST_MISSING_PARAMS(1001, "Request is missing parameters"),
    INVALID_NOTIFICATION_TYPE(1002, "Notification type is invalid"),
    EMAIL_ADDRESS_EMPTY(1003, "Email address is empty"),
    INVALID_EMAIL_FORMAT(1004, "Email address is in an incorrect format"),
    PW_EMPTY(1005, "Password is empty"),
    INVALID_PW_LENGTH(
            1006, "Password must be at least 8 characters and not longer than 256 characters"),
    INVALID_PW_CHARS(1007, "Password must contain a number, but not contain only numbers"),
    INVALID_LOGIN_CREDS(1008, "Invalid login credentials"),
    ACCT_WITH_EMAIL_EXISTS(1009, "An account with this email address already exists"),
    ACCT_DOES_NOT_EXIST(1010, "An account with this email address does not exist"),
    PHONE_NUMBER_MISSING(1011, "Phone number is missing"),
    INVALID_PHONE_NUMBER(1012, "Phone number is invalid"),
    INVALID_UPDATE_PROFILE_TYPE(1013, "Update profile type is invalid"),
    PHONE_NUMBER_NOT_REGISTERED(1014, "Phone number is not registered"),
    CLIENT_NOT_FOUND(1015, "Client not found"),
    INVALID_REDIRECT_URI(1016, "Invalid Redirect URI"),
    INVALID_USER_JOURNEY(1017, "Invalid transition in user journey"),
    INVALID_CLIENT_SESSION_ID(1018, "Client-Session-Id is missing or invalid"),
    EMAIL_ADDRESSES_MATCH(1019, "Email addresses are the same"),
    INVALID_OTP(1020, "Invalid OTP code"),
    INVALID_PW_RESET_CODE(1021, "User entered invalid password reset code"),
    TOO_MANY_PW_RESET_REQUESTS(1022, "User has requested too many password resets"),
    BLOCKED_FOR_PW_RESET_REQUEST(1023, "User cannot request another password reset"),
    NEW_PW_MATCHES_OLD(1024, "New password cannot be the same as current password"),
    TOO_MANY_MFA_OTPS_SENT(1025, "User has sent too many MFA OTP codes"),
    BLOCKED_FOR_SENDING_MFA_OTPS(1026, "User is blocked from sending any MFA OTP codes"),
    TOO_MANY_INVALID_MFA_OTPS_ENTERED(1027, "User has entered invalid mfa code too many times"),
    TOO_MANY_INVALID_PW_ENTERED(1028, "User has entered the incorrect password too many times"),
    TOO_MANY_EMAIL_CODES_SENT(1029, "System has sent too many email verifications codes"),
    TOO_MANY_PHONE_VERIFICATION_CODES_SENT(
            1030, "System has sent too many phone verifications codes"),
    BLOCKED_FOR_EMAIL_VERIFICATION_CODES(
            1031, "System is blocked from sending any email verifications codes"),
    BLOCKED_FOR_PHONE_VERIFICATION_CODES(
            1032, "System is blocked from sending any phone verifications codes"),
    TOO_MANY_EMAIL_CODES_ENTERED(
            1033, "User entered invalid email verification code too many times"),
    TOO_MANY_PHONE_CODES_ENTERED(
            1034, "User entered invalid phone verification code too many times"),
    INVALID_MFA_CODE_ENTERED(1035, "User entered invalid mfa code"),
    INVALID_EMAIL_CODE_ENTERED(1036, "User entered invalid email verification code"),
    INVALID_PHONE_CODE_ENTERED(1037, "User entered invalid phone verification code"),
    INVALID_AUTH_REQUEST(1038, "Invalid Authentication Request"),
    TOO_MANY_INVALID_PW_RESET_CODES_ENTERED(
            1039, "User entered invalid password reset code too many times"),
    PW_TOO_COMMON(1040, "Password is too common"),
    INVALID_AUTH_APP_SECRET(1041, "Auth app secret is invalid"),
    TOO_MANY_INVALID_AUTH_APP_CODES_ENTERED(
            1042, "User entered invalid authenticator app verification code too many times"),
    INVALID_AUTH_APP_CODE_ENTERED(1043, "User entered invalid authenticator app code"),
    NEW_PHONE_NUMBER_ALREADY_IN_USE(1044, "New phone number is the same as current phone number"),
    ACCT_TEMPORARILY_LOCKED(1045, "User account is temporarily locked from sign in"),
    TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_SENT(
            1046,
            "System has sent too many email verification codes for changing how to receive security codes"),
    BLOCKED_FOR_EMAIL_CODES_FOR_MFA_RESET(
            1047,
            "System is blocked from sending any email verification codes for changing how to receive security codes"),
    TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED(
            1048,
            "User entered invalid email verification code for changing how to receive security codes too many times"),
    EMAIL_HAS_NO_USER_PROFILE(1049, "Email from session does not have a user profile"),
    AUTHORIZATION_AUTH_CODE_DISABLED(1050, "Authorization Auth Code not enabled"),
    ACCT_INTERVENTIONS_API_THROTTLED(1051, "Account Interventions API throttled"),
    ACCT_INTERVENTIONS_SERVER_ERROR(1052, "Account Interventions API response Server Error"),
    ACCT_INTERVENTIONS_BAD_GATEWAY(1053, "Account Interventions API Bad Gateway"),
    ACCT_INTERVENTIONS_GATEWAY_TIMEOUT(1054, "Account Interventions API Gateway Timeout"),
    ACCT_INTERVENTIONS_UNEXPECTED_ERROR(1055, "Account Interventions API Unexpected Error"),
    USER_NOT_FOUND(1056, "User not found or no match"),
    TOO_MANY_INVALID_REAUTH_ATTEMPTS(
            1057, "User entered invalid reauth sign in details too many times"),
    UNSUCCESSFUL_IPV_TOKEN_RESPONSE(1058, "IPV TokenResponse was not successful"),
    REVERIFICATION_RESULT_GET_ERROR(1059, "Error getting reverification result"),
    MFA_RESET_JAR_GENERATION_ERROR(1060, "Failed to generate MFA Reset Authorize JAR for IPV"),
    IPV_STATE_MISMATCH(1061, "State returned from IPV does not match expected state"),
    INVALID_MFA_METHOD(1062, "Invalid MFAMethod"),
    MM_API_NOT_AVAILABLE(1063, "New method management api not available in environment"),
    MFA_METHODS_RETRIEVAL_ERROR(1064, "Error retrieving mfa methods"),
    MFA_METHOD_NOT_FOUND(1065, "Mfa method not found"),
    CANNOT_DELETE_DEFAULT_MFA(1066, "Cannot delete default priority mfa method"),
    CANNOT_DELETE_MFA_FOR_UNMIGRATED_USER(1067, "Cannot delete mfa method for non-migrated user"),
    MFA_METHOD_COUNT_LIMIT_REACHED(1068, "MFA method count limit reached"),
    SMS_MFA_WITH_NUMBER_EXISTS(1069, "SMS MFA with same number already exists"),
    AUTH_APP_EXISTS(1070, "AUTH APP MFA already exists"),
    UNEXPECTED_ACCT_MGMT_ERROR(1071, "Account Management API encountered Unexpected Error"),
    CANNOT_CHANGE_MFA_TYPE(1072, "Cannot change type of mfa method"),
    CANNOT_CHANGE_DEFAULT_MFA_PRIORITY(1073, "Cannot change priority of default mfa method"),
    CANNOT_UPDATE_PRIMARY_SMS_TO_BACKUP_NUMBER(
            1074, "Cannot update primary sms number to number already in use by backup"),
    CANNOT_UPDATE_BACKUP_SMS_NUMBER(1075, "Cannot update a backup sms mfa method's phone number"),
    CANNOT_UPDATE_BACKUP_SMS_CREDENTIAL(
            1076, "Cannot update a backup sms mfa method's auth app credential"),
    CANNOT_EDIT_BACKUP_MFA(1077, "Cannot edit a backup mfa method"),
    AUTH_APP_MFA_ID_ERROR(1078, "Unexpected error creating mfa identifier for auth app mfa method"),
    INVALID_PRINCIPAL(1079, "Invalid principal in request"),
    DEFAULT_MFA_ALREADY_EXISTS(1080, "Default method already exists, new one cannot be created."),
    AUTH_APP_METHOD_NOT_FOUND(
            1081, "Attempting to validate auth app code for user without auth app method"),
    CANNOT_ADD_SECOND_AUTH_APP(1082, "Cannot add a second auth app."),
    ACCT_SUSPENDED(1083, "User's account is suspended"),
    ACCT_BLOCKED(1084, "User's account is blocked"),
    NO_USER_PROFILE_FOR_EMAIL(1085, "Email from request does not have a user profile"),
    USER_DOES_NOT_HAVE_ACCOUNT(1086, "Email from request does not have any user credentials"),
    FAILED_TO_RAISE_AUDIT_EVENT(1087, "Failed to raise an audit event"),
    STORAGE_LAYER_ERROR(1088, "Error retrieving account details"),
    EMAIL_ADDRESS_DENIED(1089, "Email address is denied"),
    UNHANDLED_NEGATIVE_DECISION(1090, "Permissions manager negative decision was not handled"),
    INTERNATIONAL_PHONE_NUMBER_NOT_SUPPORTED(1091, "International phone numbers are not supported"),
    UNEXPECTED_INTERNAL_API_ERROR(1071, "Internal API encountered an unexpected error"),
    // Passkeys
    PASSKEY_ASSERTION_INVALID_PKC(1100, "Invalid passkey PKC object"),
    PASSKEY_ASSERTION_FAILED(1101, "Passkey assertion failed");

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
