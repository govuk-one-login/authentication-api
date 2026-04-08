package uk.gov.di.authentication.frontendapi.entity.amc;

public enum AMCScope {
    ACCOUNT_DELETE("account-delete"),
    PASSKEY_CREATE("passkey-create");

    private final String value;

    AMCScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
