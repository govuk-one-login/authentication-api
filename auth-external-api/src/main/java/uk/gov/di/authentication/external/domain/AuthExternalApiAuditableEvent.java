package uk.gov.di.authentication.external.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum AuthExternalApiAuditableEvent implements AuditableEvent {
    TOKEN_SENT_TO_ORCHESTRATION,
    USERINFO_SENT_TO_ORCHESTRATION;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
