package uk.gov.di.orchestration.shared.entity;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum IdentityAuditableEvent implements AuditableEvent {
    PROCESSING_IDENTITY_REQUEST;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
