package uk.gov.di.orchestration.shared.entity;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

public enum ValidClaims {
    ADDRESS("https://vocab.account.gov.uk/v1/address"),
    PASSPORT("https://vocab.account.gov.uk/v1/passport"),
    DRIVING_PERMIT("https://vocab.account.gov.uk/v1/drivingPermit"),
    CORE_IDENTITY_JWT("https://vocab.account.gov.uk/v1/coreIdentityJWT"),
    RETURN_CODE("https://vocab.account.gov.uk/v1/returnCode"),
    INHERITED_IDENTITY_JWT("https://vocab.account.gov.uk/v1/inheritedIdentityJWT");
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

    public static List<String> allOneLoginClaims() {
        var claims =
                Stream.of(
                                "sub",
                                "email",
                                "email_verified",
                                "phone_number",
                                "phone_number_verified",
                                "wallet_subject_id")
                        .collect(toList());

        claims.addAll(getAllValidClaims());

        return claims;
    }

    public static boolean isValidClaim(String claim) {
        return Arrays.stream(ValidClaims.values())
                .map(ValidClaims::getValue)
                .anyMatch(t -> t.equals(claim));
    }
}
