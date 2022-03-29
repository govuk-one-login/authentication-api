package uk.gov.di.authentication.ipv.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum IPVAuditableEvent implements AuditableEvent {
    IPV_AUTHORISATION_REQUESTED,
    IPV_CAPACITY_REQUESTED,
    SPOT_RESPONSE_RECEIVED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
