package uk.gov.di.orchestration.shared.domain;

@SuppressWarnings("java:S6548")
public enum TokenGeneratedAuditableEvent implements AuditableEvent {
    OIDC_TOKEN_GENERATED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
