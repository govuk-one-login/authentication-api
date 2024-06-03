package uk.gov.di.authentication.oidc.domain;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum OidcAuditableEvent implements AuditableEvent {
    AUTHORISATION_REQUEST_ERROR,
    AUTHORISATION_INITIATED,
    AUTHORISATION_REQUEST_RECEIVED,
    AUTHORISATION_REQUEST_PARSED,
    AUTHENTICATION_COMPLETE,
    AUTH_CODE_ISSUED,
    USER_INFO_RETURNED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
