package uk.gov.di.authentication.shared.services.mfa;

public enum MfaRetrieveFailureReason {
    UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP,
    USER_DOES_NOT_HAVE_ACCOUNT,
    UNKNOWN_MFA_IDENTIFIER
}
