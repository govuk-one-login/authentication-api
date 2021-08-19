package uk.gov.di.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum OidcAuditableEvent implements AuditableEvent {
    AUTHORISATION_REQUEST_RECEIVED
}
