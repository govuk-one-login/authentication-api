package uk.gov.di.authentication.shared.services.mfa;

public enum MfaDeleteFailureReason {
    CANNOT_DELETE_DEFAULT_METHOD,
    MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST
}
