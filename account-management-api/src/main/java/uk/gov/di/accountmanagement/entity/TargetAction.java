package uk.gov.di.accountmanagement.entity;

public enum TargetAction {
    UPDATE_EMAIL,
    UPDATE_PASSWORD,
    DELETE_ACCOUNT,
    UPDATE_MFA;

    public String getValue() {
        return name();
    }
}
