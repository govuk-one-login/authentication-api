package uk.gov.di.orchestration.shared.domain;

@SuppressWarnings("java:S6548")
public enum LogoutAuditableEvent implements AuditableEvent {
    LOG_OUT_SUCCESS;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
