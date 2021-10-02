package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

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

    public static List<CredentialTrustLevel> retrieveListOfCredentialTrustLevels(
            List<String> vtrSets) {
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
                .collect(Collectors.toList());
    }

    public static CredentialTrustLevel getDefault() {
        return MEDIUM_LEVEL;
    }
}
