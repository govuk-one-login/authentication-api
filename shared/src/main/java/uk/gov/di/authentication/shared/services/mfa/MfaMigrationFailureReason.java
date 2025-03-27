package uk.gov.di.authentication.shared.services.mfa;

public enum MfaMigrationFailureReason {
    NO_USER_PROFILE_FOUND_FOR_EMAIL,
    PHONE_NUMBER_ALREADY_MIGRATED,
    PHONE_NUMBER_NOT_VERIFIED
}
