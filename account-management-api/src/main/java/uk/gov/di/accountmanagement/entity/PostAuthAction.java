package uk.gov.di.accountmanagement.entity;

public enum PostAuthAction {
    UPDATE_EMAIL,
    UPDATE_PASSWORD,
    DELETE_ACCOUNT;

    public String getValue() {
        return name();
    }
}
