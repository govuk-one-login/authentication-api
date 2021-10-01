package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;

class ValidScopesTest {

    @Test
    void shouldReturnCorrectClaimsForOpenidScope() {
        assertThat(ValidScopes.getClaimsForListOfScopes(List.of("openid")), contains("sub"));
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("openid")).size(), 1);
    }

    @Test
    void shouldReturnCorrectClaimsForEmailScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("email")),
                containsInAnyOrder("email", "email_verified"));
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("email")).size(), 2);
    }

    @Test
    void shouldNotReturnAnyClaimsForOfflineAccessScope() {
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("offline_access")).size(), 0);
    }

    @Test
    void shouldReturnCorrectClaimsForPhoneScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("phone")),
                containsInAnyOrder("phone_number", "phone_number_verified"));
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("phone")).size(), 2);
    }

    @Test
    void shouldReturnCorrectClaimsForAmScope() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("am")),
                containsInAnyOrder("read", "write"));
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("am")).size(), 2);
    }

    @Test
    void shouldReturnCorrectClaimsForOIDCAndCustomScopes() {
        assertThat(
                ValidScopes.getClaimsForListOfScopes(List.of("openid", "am")),
                containsInAnyOrder("sub", "read", "write"));
        assertEquals(ValidScopes.getClaimsForListOfScopes(List.of("openid", "am")).size(), 3);
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
        assertEquals(
                ValidScopes.getClaimsForListOfScopes(
                                List.of("openid", "email", "phone", "am", "offline_access"))
                        .size(),
                7);
    }

    @Test
    void shouldReturnAllValidScopesInCorrectOrder() {
        assertThat(
                ValidScopes.getAllValidScopes(),
                contains("openid", "email", "phone", "offline_access", "am", "govuk-account"));
    }

    @Test
    void shouldReturnCorrectNumberOfValidScopes() {
        assertEquals(ValidScopes.getAllValidScopes().size(), 6);
    }

    @Test
    void shouldNotReturnPrivateScopesWhenPublicRequested() {
        assertEquals(ValidScopes.getPublicValidScopes().size(), 4);
        assertThat(
                ValidScopes.getPublicValidScopes(),
                contains("openid", "email", "phone", "offline_access"));
        assertThat(ValidScopes.getPublicValidScopes(), not(contains("am")));
    }

    @Test
    void shouldReturnOIDCScopesForWellKnown() {
        Scope scope = ValidScopes.getScopesForWellKnownHandler();
        assertEquals(scope.toString(), "openid,email,phone,offline_access");
    }

    @Test
    void shouldReturnScopesForListOfValidClaims() {
        Set<String> claims =
                Set.of(
                        "sub",
                        "email",
                        "email_verified",
                        "phone_number",
                        "phone_number_verified",
                        "read",
                        "write");

        assertEquals(ValidScopes.getScopesForListOfClaims(claims).size(), 5);
    }

    @Test
    void shouldNotReturnEmailScopesWhenAllEmailsClaimsAreNotGiven() {
        Set<String> claims =
                Set.of("sub", "email", "phone_number", "phone_number_verified", "read", "write");

        assertEquals(ValidScopes.getScopesForListOfClaims(claims).size(), 4);
        assertFalse(
                ValidScopes.getScopesForListOfClaims(claims)
                        .contains(OIDCScopeValue.EMAIL.getValue()));
    }
}
