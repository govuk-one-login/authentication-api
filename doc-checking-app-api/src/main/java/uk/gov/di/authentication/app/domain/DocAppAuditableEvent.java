package uk.gov.di.authentication.app.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum DocAppAuditableEvent implements AuditableEvent {
    DOC_APP_AUTHORISATION_REQUESTED,
    DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
    DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
