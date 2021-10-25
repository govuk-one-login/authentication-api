package uk.gov.di.authentication.frontendapi.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum FrontendAuditableEvent implements AuditableEvent {
    ACCOUNT_TEMPORARILY_LOCKED,
    INVALID_CREDENTIALS,
    NO_ACCOUNT_WITH_EMAIL,
    LOG_IN_SUCCESS
}
