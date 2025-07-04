package uk.gov.di.authentication.shared.domain;

public interface AuditableEvent {
    String AUDIT_EVENT_EXTENSIONS_MFA_METHOD = "mfa-method";
    String AUDIT_EVENT_EXTENSIONS_MFA_TYPE = "mfa-type";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY = "account-recovery";
    String AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE = "journey-type";
    String AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE = "phone_number_country_code";
    String AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT = "attemptNoFailedAt";

    AuditableEvent parseFromName(String name);
}
