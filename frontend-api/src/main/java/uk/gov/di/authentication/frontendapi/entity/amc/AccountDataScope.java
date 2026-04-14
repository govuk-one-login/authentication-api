package uk.gov.di.authentication.frontendapi.entity.amc;

public enum AccountDataScope implements ExternalApiScope {
    PASSKEY_CREATE("passkey-create");

    private final String value;

    AccountDataScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
