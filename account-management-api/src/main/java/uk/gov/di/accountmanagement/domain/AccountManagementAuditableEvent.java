package uk.gov.di.accountmanagement.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum AccountManagementAuditableEvent implements AuditableEvent {
    UPDATE_EMAIL,
    UPDATE_PASSWORD,
    DELETE_ACCOUNT
}
