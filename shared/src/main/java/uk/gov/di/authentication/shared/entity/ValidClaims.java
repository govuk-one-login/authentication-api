package uk.gov.di.authentication.shared.entity;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class ValidClaims {

    public static final String NAME = "name";
    public static final String ADDRESS = "address";
    public static final String PASSPORT_NUMBER = "passport-number";
    public static final String BIRTHDATE = "birthdate";

    protected static final Collection<ClaimsSetRequest.Entry> allowedClaims =
            new ClaimsSetRequest()
                    .add(NAME)
                    .add(BIRTHDATE)
                    .add(ADDRESS)
                    .add(PASSPORT_NUMBER)
                    .getEntries();

    private ValidClaims() {}

    public static Set<String> getAllowedClaimNames() {
        return allowedClaims.stream()
                .map(ClaimsSetRequest.Entry::getClaimName)
                .collect(Collectors.toSet());
    }
}
