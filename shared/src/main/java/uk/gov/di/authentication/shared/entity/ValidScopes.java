package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValidScopes {

    private static final List<OIDCScopeValue> allowedOIDCScopes =
            List.of(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);

    private static final List<CustomScopeValue> allowedCustomScopes =
            List.of(CustomScopeValue.ACCOUNT_MANAGEMENT);

    private ValidScopes() {}

    private static Set<String> getClaimsForScope(String scope) {
        for (OIDCScopeValue scopeValue : allowedOIDCScopes) {
            if (scopeValue.getValue().equals(scope)) {
                return scopeValue.getClaimNames();
            }
        }
        for (CustomScopeValue scopeValue : allowedCustomScopes) {
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

    public static List<String> getAllValidScopes() {
        return Stream.concat(
                        allowedOIDCScopes.stream().map(Identifier::getValue),
                        allowedCustomScopes.stream().map(Identifier::getValue))
                .collect(Collectors.toList());
    }

    public static List<String> getPublicValidScopes() {
        return Stream.concat(
                        allowedOIDCScopes.stream().map(Identifier::getValue),
                        allowedCustomScopes.stream()
                                .filter(CustomScopeValue::isPublicScope)
                                .map(Identifier::getValue))
                .collect(Collectors.toList());
    }

    public static Scope getScopesForWellKnownHandler() {
        return new Scope(
                allowedOIDCScopes.stream()
                        .map(Identifier::getValue)
                        .collect(Collectors.joining(",")));
    }
}
