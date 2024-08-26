package uk.gov.di.authentication.utils.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum UtilsAuditableEvent implements AuditableEvent {
    AUTH_BULK_EMAIL_SENT,
    AUTH_BULK_RETRY_EMAIL_SENT;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
