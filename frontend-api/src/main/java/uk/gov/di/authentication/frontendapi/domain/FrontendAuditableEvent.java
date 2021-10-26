package uk.gov.di.authentication.frontendapi.domain;

import uk.gov.di.authentication.shared.domain.AuditableEvent;

public enum FrontendAuditableEvent implements AuditableEvent {
    ACCOUNT_TEMPORARILY_LOCKED,
    INVALID_CREDENTIALS,
    NO_ACCOUNT_WITH_EMAIL,
    CODE_MAX_RETRIES_REACHED,
    CODE_VERIFIED,
    PASSWORD_RESET_REQUESTED,
    LOG_IN_SUCCESS,
    CHECK_USER_INVALID_EMAIL,
    CHECK_USER_NO_ACCOUNT_WITH_EMAIL,
    CHECK_USER_KNOWN_EMAIL,
    CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
    CREATE_ACCOUNT
}
