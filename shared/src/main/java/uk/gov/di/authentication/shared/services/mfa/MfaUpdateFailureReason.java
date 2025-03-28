package uk.gov.di.authentication.shared.services.mfa;

public enum MfaUpdateFailureReason {
    CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD,
    CANNOT_CHANGE_TYPE_OF_MFA_METHOD,
    REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
    UNKOWN_MFA_IDENTIFIER,
    ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER,
    UNEXPECTED_ERROR
}
