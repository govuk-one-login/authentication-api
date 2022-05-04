package uk.gov.di.authentication.shared.entity;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class ValidClaims {

    public static final String ADDRESS = "https://vocab.account.gov.uk/v1/address";
    public static final String PASSPORT = "https://vocab.account.gov.uk/v1/passport";
    public static final String CORE_IDENTITY_JWT =
            "https://vocab.account.gov.uk/v1/coreIdentityJWT";

    protected static final Collection<ClaimsSetRequest.Entry> allowedClaims =
            new ClaimsSetRequest().add(CORE_IDENTITY_JWT).add(ADDRESS).add(PASSPORT).getEntries();

    private ValidClaims() {}

    public static Set<String> getAllowedClaimNames() {
        return allowedClaims.stream()
                .map(ClaimsSetRequest.Entry::getClaimName)
                .collect(Collectors.toSet());
    }

    public static boolean isValidClaim(String claim) {
        return allowedClaims.stream().anyMatch(t -> t.getClaimName().equals(claim));
    }
}
