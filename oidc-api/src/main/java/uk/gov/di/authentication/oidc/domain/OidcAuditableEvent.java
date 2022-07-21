package uk.gov.di.authentication.oidc.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum OidcAuditableEvent implements AuditableEvent {
    AUTHORISATION_REQUEST_ERROR,
    AUTHORISATION_INITIATED,
    AUTHORISATION_REQUEST_RECEIVED,
    AUTH_CODE_ISSUED,
    LOG_OUT_SUCCESS,
    USER_INFO_RETURNED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
