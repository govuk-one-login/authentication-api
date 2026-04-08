package uk.gov.di.authentication.shared.services.mfa;

public enum MfaMigrationFailureReason {
    NO_CREDENTIALS_FOUND_FOR_USER,
    ALREADY_MIGRATED,
    UNEXPECTED_ERROR_RETRIEVING_METHODS
}
