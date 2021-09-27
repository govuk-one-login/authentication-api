package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;

public enum CredentialTrustLevel {
    LOW_LEVEL("Cl"),
    MEDIUM_LEVEL("Cm"),
    HIGH_LEVEL("Ch"),
    VERY_HIGH_LEVEL("Cv");

    private String value;

    CredentialTrustLevel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CredentialTrustLevel parseByValue(String value) {
        return Arrays.stream(values())
                .filter(c -> c.getValue().equals(value))
                .findFirst()
                .orElseThrow(
                        () ->
                                new IllegalArgumentException(
                                        value + " is not a valid CredentialTrustLevel"));
    }
}
