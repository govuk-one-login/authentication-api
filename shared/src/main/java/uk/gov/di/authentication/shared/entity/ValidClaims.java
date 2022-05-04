package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum ValidClaims {
    ADDRESS("https://vocab.account.gov.uk/v1/address"),
    PASSPORT("https://vocab.account.gov.uk/v1/passport"),
    CORE_IDENTITY_JWT("https://vocab.account.gov.uk/v1/coreIdentityJWT");

    private final String value;

    ValidClaims(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Set<String> getAllValidClaims() {
        return Arrays.stream(ValidClaims.values())
                .map(ValidClaims::getValue)
                .collect(Collectors.toSet());
    }

    public static boolean isValidClaim(String claim) {
        return Arrays.stream(ValidClaims.values())
                .map(ValidClaims::getValue)
                .anyMatch(t -> t.equals(claim));
    }
}
