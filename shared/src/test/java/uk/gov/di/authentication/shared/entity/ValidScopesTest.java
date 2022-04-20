package uk.gov.di.authentication.shared.entity;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ValidScopesTest {

    @Test
    void shouldReturnCorrectClaimsForOpenidScope() {
        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("openid")), contains("sub"));
        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("openid")).size(), equalTo(1));
    }

    @Test
    void shouldReturnCorrectClaimsForEmailScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("email")),
                containsInAnyOrder("email", "email_verified"));
        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("email")).size(), equalTo(2));
    }

    @Test
    void shouldNotReturnAnyClaimsForOfflineAccessScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("offline_access")).size(), equalTo(0));
    }

    @Test
    void shouldReturnCorrectClaimsForPhoneScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("phone")),
                containsInAnyOrder("phone_number", "phone_number_verified"));
        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("phone")).size(), equalTo(2));
    }

    @Test
    void shouldReturnCorrectClaimsForAmScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("am")),
                containsInAnyOrder("read", "write"));

        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("am")).size(), equalTo(2));
    }

    @Test
    void shouldReturnCorrectClaimsForDocCheckingAppScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("doc-checking-app")),
                containsInAnyOrder("read"));
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("doc-checking-app")).size(),
                equalTo(1));
    }

    @Test
    void shouldReturnCorrectClaimsForGovUkAccountScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("govuk-account")),
                containsInAnyOrder("read"));
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("govuk-account")).size(), equalTo(1));
    }

    @Test
    void shouldReturnCorrectClaimsForOIDCAndCustomScopes() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("openid", "am")),
                containsInAnyOrder("sub", "read", "write"));
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("openid", "am")).size(), equalTo(3));
    }

    @Test
    void shouldReturnCorrectClaimsForAllOIDCAndCustomScopes() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(
                        List.of("openid", "email", "phone", "am", "offline_access")),
                containsInAnyOrder(
                        "sub",
                        "email",
                        "email_verified",
                        "phone_number",
                        "phone_number_verified",
                        "read",
                        "write"));

        assertThat(
                ValidScopes.getClaimsForListOfScopes(
                                List.of("openid", "email", "phone", "am", "offline_access"))
                        .size(),
                equalTo(7));
    }

    @Test
    void shouldReturnAllValidScopesInCorrectOrder() {
        assertThat(
                ValidScopes.getAllValidScopes(),
                contains(
                        "openid",
                        "email",
                        "phone",
                        "offline_access",
                        "am",
                        "govuk-account",
                        "doc-checking-app"));
    }

    @Test
    void shouldReturnCorrectNumberOfValidScopes() {
        assertThat(ValidScopes.getAllValidScopes().size(), equalTo(7));
    }

    @Test
    void shouldNotReturnPrivateScopesWhenPublicRequested() {
        assertThat(ValidScopes.getPublicValidScopes().size(), equalTo(4));
        assertThat(
                ValidScopes.getPublicValidScopes(),
                contains("openid", "email", "phone", "offline_access"));
        assertThat(ValidScopes.getPublicValidScopes(), not(contains("am")));
    }

    @Test
    void shouldReturnOIDCScopesForWellKnown() {
        var scope = ValidScopes.getScopesForWellKnownHandler();
        assertThat(
                scope.toStringList(),
                equalTo(List.of("openid", "email", "phone", "offline_access")));
    }

    @Test
    void shouldReturnScopesForListOfValidClaims() {
        var claims =
                Set.of(
                        "sub",
                        "email",
                        "email_verified",
                        "phone_number",
                        "phone_number_verified",
                        "read",
                        "write");

        assertThat(ValidScopes.getScopesForListOfClaims(claims).size(), equalTo(6));
    }

    @Test
    void shouldNotReturnEmailScopesWhenAllEmailsClaimsAreNotGiven() {
        var claims =
                Set.of("sub", "email", "phone_number", "phone_number_verified", "read", "write");

        assertThat(ValidScopes.getScopesForListOfClaims(claims).size(), equalTo(5));
        assertFalse(
                ValidScopes.getScopesForListOfClaims(claims)
                        .contains(OIDCScopeValue.EMAIL.getValue()));
    }
}
