package uk.gov.di.authentication.ipv.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum IPVAuditableEvent implements AuditableEvent {
    IPV_AUTHORISATION_REQUESTED,
    IPV_AUTHORISATION_RESPONSE_RECEIVED,
    IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
    IPV_CAPACITY_REQUESTED,
    IPV_SPOT_REQUESTED,
    SPOT_SUCCESSFUL_RESPONSE_RECEIVED,
    SPOT_UNSUCCESSFUL_RESPONSE_RECEIVED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
