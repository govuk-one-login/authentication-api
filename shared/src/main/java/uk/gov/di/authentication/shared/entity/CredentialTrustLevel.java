package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public enum CredentialTrustLevel {
    LOW_LEVEL("Cl"),
    MEDIUM_LEVEL("Cl.Cm");

    private String value;

    CredentialTrustLevel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CredentialTrustLevel retrieveCredentialTrustLevel(List<String> vtrSets) {

        return Arrays.stream(values())
                .filter(
                        tl ->
                                vtrSets.stream()
                                        .anyMatch(
                                                set ->
                                                        new HashSet<>(
                                                                        Arrays.asList(
                                                                                set.split("\\.")))
                                                                .equals(
                                                                        new HashSet<>(
                                                                                Arrays.asList(
                                                                                        tl.getValue()
                                                                                                .split(
                                                                                                        "\\."))))))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid CredentialTrustLevel"));
    }

    public static CredentialTrustLevel retrieveCredentialTrustLevel(String vtrSets) {

        return Arrays.stream(values())
                .filter(tl -> vtrSets.equals(tl.getValue()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid CredentialTrustLevel"));
    }

    public static CredentialTrustLevel getDefault() {
        return MEDIUM_LEVEL;
    }
}
