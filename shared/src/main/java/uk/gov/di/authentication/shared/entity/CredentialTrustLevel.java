package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
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
                .filter(c -> vtrSets.stream().anyMatch(c.getValue()::equals))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid CredentialTrustLevel"));
    }

    public static List<CredentialTrustLevel> retrieveListOfCredentialTrustLevels(
            List<String> vtrSets) {
        return Arrays.stream(values())
                .filter(c -> vtrSets.stream().anyMatch(c.getValue()::equals))
                .collect(Collectors.toList());
    }

    public static CredentialTrustLevel getDefault() {
        return MEDIUM_LEVEL;
    }
}
