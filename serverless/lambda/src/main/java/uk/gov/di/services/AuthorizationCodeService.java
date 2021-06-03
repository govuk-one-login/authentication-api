package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AuthorizationCodeService {
    private Map<AuthorizationCode, String> issuedCodes = new HashMap<>();

    public AuthorizationCode issueCodeForUser(String email) {
        AuthorizationCode authorizationCode = new AuthorizationCode();
        issuedCodes.put(authorizationCode, email);

        return authorizationCode;
    }

    public Optional<String> getEmailForCode(AuthorizationCode authorizationCode) {
        String email = issuedCodes.get(authorizationCode);
        issuedCodes.remove(authorizationCode);

        return Optional.ofNullable(email);
    }
}
