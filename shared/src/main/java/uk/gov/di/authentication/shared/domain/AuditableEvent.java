package uk.gov.di.authentication.shared.domain;

public interface AuditableEvent {
    String AUDIT_EVENT_EXTENSIONS_MFA_METHOD = "mfa-method";
    String AUDIT_EVENT_EXTENSIONS_MFA_TYPE = "mfa-type";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY = "account-recovery";
    String AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE = "journey-type";
    // Note: this (phone number country code) is unlikely to be needed to set explicitly on events
    // as it is handled by the audit service: we should remove it from here when it's been removed
    // from all the metadata pairs explicitly set in handlers to discourage use
    String AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE = "phone_number_country_code";
    String AUDIT_EVENT_EXTENSIONS_MIGRATION_SUCCEEDED = "migration-succeeded";
    String AUDIT_EVENT_EXTENSIONS_HAD_PARTIAL = "had-partial";
    String AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT = "attemptNoFailedAt";
    String AUDIT_EVENT_EXTENSIONS_NOTIFICATION_TYPE = "notification-type";
    String AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED = "MFACodeEntered";
    String AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE = "mfaResetType";

    AuditableEvent parseFromName(String name);
}
