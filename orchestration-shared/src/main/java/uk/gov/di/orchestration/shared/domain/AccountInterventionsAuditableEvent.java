package uk.gov.di.orchestration.shared.domain;

public enum AccountInterventionsAuditableEvent implements AuditableEvent {
    AIS_RESPONSE_RECEIVED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
