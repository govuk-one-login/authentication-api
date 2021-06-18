package uk.gov.di.entity;

public enum SessionState {
    NEW,
    USER_NOT_FOUND,
    AUTHENTICATION_REQUIRED,
    TWO_FACTOR_REQUIRED,
    AUTHENTICATED
}
