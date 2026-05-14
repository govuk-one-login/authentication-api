package uk.gov.di.authentication.frontendapi.entity.amc;

import uk.gov.di.authentication.shared.entity.AccessTokenScope;

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
