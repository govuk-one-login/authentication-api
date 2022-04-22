package uk.gov.di.authentication.app.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum DocAppAuditableEvent implements AuditableEvent {
    DOC_APP_AUTHORISATION_REQUESTED;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
