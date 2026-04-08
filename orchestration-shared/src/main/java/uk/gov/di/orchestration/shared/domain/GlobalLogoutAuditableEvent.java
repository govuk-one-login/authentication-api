package uk.gov.di.orchestration.shared.domain;

public enum GlobalLogoutAuditableEvent implements AuditableEvent {
    GLOBAL_LOG_OUT_SUCCESS;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
