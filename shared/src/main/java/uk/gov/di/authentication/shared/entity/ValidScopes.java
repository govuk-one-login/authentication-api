package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValidScopes {

    private static final List<OIDCScopeValue> allowedOIDCScopes =
            List.of(
                    OIDCScopeValue.OPENID,
                    OIDCScopeValue.EMAIL,
                    OIDCScopeValue.PHONE,
                    OIDCScopeValue.OFFLINE_ACCESS);

    private static final List<CustomScopeValue> allowedCustomScopes =
            List.of(CustomScopeValue.ACCOUNT_MANAGEMENT, CustomScopeValue.GOVUK_ACCOUNT);

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
            if (scope.equals(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
                break;
            }
            claims.addAll(ValidScopes.getClaimsForScope(scope));
        }
        return claims;
    }

    public static List<String> getScopesForListOfClaims(Set<String> claims) {
        List<String> scopesToReturn = new ArrayList<>();
        for (OIDCScopeValue scope : allowedOIDCScopes) {
            if (scope.equals(OIDCScopeValue.OFFLINE_ACCESS)) {
                break;
            }
            if (claims.containsAll(scope.getClaimNames())) {
                scopesToReturn.add(scope.getValue());
            }
        }
        for (CustomScopeValue scope : allowedCustomScopes) {
            if (claims.containsAll(scope.getClaimNames())) {
                scopesToReturn.add(scope.getValue());
            }
        }
        return scopesToReturn;
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
        List<String> scopeValues =
                allowedOIDCScopes.stream().map(Identifier::getValue).collect(Collectors.toList());
        Scope scope = new Scope();
        for (String scopeValue : scopeValues) {
            scope.add(scopeValue);
        }
        return scope;
    }
}
