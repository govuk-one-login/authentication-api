package uk.gov.di.authentication.shared.domain;

public interface AuditableEvent {
    String AUDIT_EVENT_EXTENSIONS_MFA_METHOD = "mfa-method";
    String AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY = "account-recovery";
    String AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE = "journey-type";

    AuditableEvent parseFromName(String name);
}
