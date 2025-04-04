package uk.gov.di.authentication.shared.services.mfa;

public enum MfaRetrieveFailureReason {
    ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA,
    UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP
}
