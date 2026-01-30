package uk.gov.di.authentication.frontendapi.entity;

public enum AMCScope {
    ACCOUNT_DELETE("account-delete");

    private final String value;

    AMCScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
