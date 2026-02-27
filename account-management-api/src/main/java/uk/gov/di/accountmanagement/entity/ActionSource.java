package uk.gov.di.accountmanagement.entity;

public enum ActionSource {
    ACCOUNT_MANAGEMENT,
    ACCOUNT_COMPONENTS;

    public String getValue() {
        return name();
    }
}
