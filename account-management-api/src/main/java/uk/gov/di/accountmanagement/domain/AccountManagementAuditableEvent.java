package uk.gov.di.accountmanagement.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum AccountManagementAuditableEvent implements AuditableEvent {
    UPDATE_EMAIL,
    UPDATE_PASSWORD,
    UPDATE_PHONE_NUMBER,
    ACCOUNT_MANAGEMENT_AUTHENTICATE,
    DELETE_ACCOUNT
}
