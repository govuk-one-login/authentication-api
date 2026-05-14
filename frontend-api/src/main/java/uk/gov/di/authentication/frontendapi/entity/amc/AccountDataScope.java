package uk.gov.di.authentication.frontendapi.entity.amc;

public enum AccountDataScope implements AccessTokenScope {
    PASSKEY_CREATE("passkey-create"),
    PASSKEY_RETRIEVE("passkey-retrieve");

    private final String value;

    AccountDataScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
