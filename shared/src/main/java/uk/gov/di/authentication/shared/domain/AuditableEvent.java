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
    String AUDIT_EVENT_EXTENSIONS_HAS_ACTIVE_PASSKEY = "has_active_passkey";
    String AUDIT_EVENT_EXTENSIONS_AMC_SCOPE = "amc_scope";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTION_OVERALL_OUTCOME = "account_action_overall_outcome";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS = "account_actions";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_ERRORS = "account_actions_errors";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_FAILED = "account_actions_failed";
    String AUDIT_EVENT_EXTENSIONS_PASSKEY = "passkey";
    String AUDIT_EVENT_EXTENSIONS_RESTRICTED_PASSKEY = "passkey";
    String AUDIT_EVENT_EXTENSIONS_RESTRICTED_PASSKEY_CREDENTIAL_ID = "passkey_credential_id";

    AuditableEvent parseFromName(String name);
}
