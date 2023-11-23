package uk.gov.di.authentication.clientregistry.domain;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum ClientRegistryAuditableEvent implements AuditableEvent {
    REGISTER_CLIENT_REQUEST_RECEIVED,
    REGISTER_CLIENT_REQUEST_ERROR,
    UPDATE_CLIENT_REQUEST_RECEIVED,
    UPDATE_CLIENT_REQUEST_ERROR;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
