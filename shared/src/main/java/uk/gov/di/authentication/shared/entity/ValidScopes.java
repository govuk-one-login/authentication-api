package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ValidScopes {

    private static final List<OIDCScopeValue> allowedScopes =
            List.of(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);

    private ValidScopes() {}

    public static Set<String> getClaimsForScope(String scope) {
        for (OIDCScopeValue scopeValue : allowedScopes) {
            if (scopeValue.getValue().equals(scope)) {
                return scopeValue.getClaimNames();
            }
        }
        return Collections.emptySet();
    }

    public static Set<String> getClaimsForListOfScopes(List<String> scopes) {
        Set<String> claims = new HashSet<>();
        for (String scope : scopes) {
            claims.addAll(ValidScopes.getClaimsForScope(scope));
        }
        return claims;
    }

    public static List<OIDCScopeValue> getAllValidScopes() {
        return allowedScopes;
    }

    public static Scope getScopesForWellKnownHandler() {
        return new Scope(
                allowedScopes.stream().map(Identifier::getValue).collect(Collectors.joining(",")));
    }
}
