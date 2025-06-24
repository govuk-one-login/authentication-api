package uk.gov.di.accountmanagement.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum AccountManagementAuditableEvent implements AuditableEvent {
    AUTH_UPDATE_EMAIL,
    AUTH_UPDATE_PASSWORD,
    AUTH_UPDATE_PHONE_NUMBER,
    AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
    AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
    AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
    AUTH_DELETE_ACCOUNT,
    AUTH_SEND_OTP,
    AUTH_EMAIL_FRAUD_CHECK_BYPASSED,
    AUTH_MFA_METHOD_MIGRATION_ATTEMPTED;

    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
