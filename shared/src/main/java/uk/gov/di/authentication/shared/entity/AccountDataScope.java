package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.Optional;

public enum AccountDataScope implements AccessTokenScope {
    PASSKEY_CREATE("passkey-create"),
    PASSKEY_RETRIEVE("passkey-retrieve"),
    PASSKEY_UPDATE("passkey-update"),
    PASSKEY_DELETE("passkey-delete");

    private final String value;

    AccountDataScope(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Optional<AccountDataScope> fromValue(String value) {
        return Arrays.stream(values()).filter(s -> s.value.equals(value)).findFirst();
    }
}
