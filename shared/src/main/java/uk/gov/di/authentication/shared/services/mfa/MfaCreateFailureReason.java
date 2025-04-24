package uk.gov.di.authentication.shared.services.mfa;

public enum MfaCreateFailureReason {
    BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST,
    PHONE_NUMBER_ALREADY_EXISTS,
    AUTH_APP_EXISTS,
    INVALID_PHONE_NUMBER
}
