package uk.gov.di.authentication.utils.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum UtilsAuditableEvent implements AuditableEvent {
    BULK_EMAIL_SENT;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
