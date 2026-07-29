package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum SPOTAuditableEvent implements AuditableEvent {
    IPV_SPOT_REQUESTED, // Not used yet, but this will be the same for IPV and SIS
    PROCESSING_IDENTITY_REQUEST;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
