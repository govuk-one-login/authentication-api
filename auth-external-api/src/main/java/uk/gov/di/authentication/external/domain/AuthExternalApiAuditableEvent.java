package uk.gov.di.authentication.external.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum AuthExternalApiAuditableEvent implements AuditableEvent {
    AUTH_TOKEN_SENT_TO_ORCHESTRATION,
    AUTH_USERINFO_SENT_TO_ORCHESTRATION;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
