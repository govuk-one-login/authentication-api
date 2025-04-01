package uk.gov.di.authentication.shared.services.mfa;

public enum MfaMigrationFailureReason {
    NO_USER_FOUND_FOR_EMAIL,
    ALREADY_MIGRATED,
    PHONE_NUMBER_NOT_VERIFIED
}
