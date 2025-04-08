package uk.gov.di.authentication.shared.services.mfa;

public enum MfaCreateFailureReason {
    INVALID_PRIORITY_IDENTIFIER,
    BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST,
    PHONE_NUMBER_ALREADY_EXISTS,
    AUTH_APP_EXISTS,
    ERROR_RETRIEVING_MFA_METHODS
}
