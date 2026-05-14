package uk.gov.di.authentication.frontendapi.entity.amc;

public enum AccountManagementScope implements AccessTokenScope {
    ACCOUNT_DELETE("account-delete");

    private final String value;

    AccountManagementScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
