package uk.gov.di.authentication.shared.testinterface;

public enum AccountManagementErrorResponse implements ErrorResponse {
    SESSION_ID_MISSING(1000, "Session-Id is missing or invalid"),
    REQUEST_MISSING_PARAMS(1001, "Request is missing parameters"),
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
    SERIALIZATION_ERROR(1097, "Failed to serialize API Gateway proxy response");

    private int code;
    private String message;

    AccountManagementErrorResponse(int code, String message) {
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
