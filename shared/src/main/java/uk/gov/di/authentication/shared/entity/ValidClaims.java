package uk.gov.di.authentication.shared.entity;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class ValidClaims {

    protected static final Collection<ClaimsSetRequest.Entry> allowedClaims =
            new ClaimsSetRequest().add("name").add("birthdate").add("address").getEntries();

    private ValidClaims() {}

    public static Set<String> getAllowedClaimNames() {
        return allowedClaims.stream()
                .map(ClaimsSetRequest.Entry::getClaimName)
                .collect(Collectors.toSet());
    }
}
