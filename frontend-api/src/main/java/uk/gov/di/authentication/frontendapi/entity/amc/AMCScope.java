package uk.gov.di.authentication.frontendapi.entity.amc;

import java.util.Arrays;
import java.util.Optional;

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

    public static Optional<AMCScope> fromValue(String value) {
        return Arrays.stream(values()).filter(s -> s.value.equals(value)).findFirst();
    }
}
