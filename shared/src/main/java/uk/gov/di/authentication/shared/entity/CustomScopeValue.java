package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class CustomScopeValue extends Scope.Value {

    public static final CustomScopeValue ACCOUNT_MANAGEMENT =
            new CustomScopeValue("am", Requirement.OPTIONAL, new String[] {"read", "write"}, true);

    public static final CustomScopeValue GOVUK_ACCOUNT =
            new CustomScopeValue(
                    "govuk-account", Requirement.OPTIONAL, new String[] {"read", "write"}, true);

    private final String[] claims;

    private boolean privateScope = true;

    private CustomScopeValue(
            final String value,
            final Requirement requirement,
            final String[] claims,
            boolean privateScope) {
        super(value, requirement);
        this.claims = claims;
        this.privateScope = privateScope;
    }

    public Set<String> getClaimNames() {
        Set<String> targetSet = new HashSet<>();
        Collections.addAll(targetSet, claims);
        return targetSet;
    }

    public boolean isPrivateScope() {
        return privateScope;
    }

    public boolean isPublicScope() {
        return !privateScope;
    }
}
