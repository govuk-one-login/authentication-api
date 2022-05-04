package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidClaimsTest {

    static Stream<String> supportedClaims() {
        return Stream.of(
                "https://vocab.account.gov.uk/v1/address",
                "https://vocab.account.gov.uk/v1/passport",
                "https://vocab.account.gov.uk/v1/coreIdentityJWT");
    }

    static Stream<String> unsupportedClaims() {
        return Stream.of(
                "https://vocab.account.gov.uk/v1/name",
                "https://vocab.account.gov.uk/v1/birthdate");
    }

    @Test
    void shouldReturnCorrectNumberOfClaimsSupported() {
        assertThat(ValidClaims.getAllValidClaims().size(), equalTo(3));
    }

    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnNamesOfSupportedClaims(String supportedClaim) {
        assertTrue(ValidClaims.getAllValidClaims().contains(supportedClaim));
    }

    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnTrueForSupportedClaims(String claimName) {
        assertTrue(ValidClaims.isValidClaim(claimName));
    }

    @ParameterizedTest
    @MethodSource("unsupportedClaims")
    void shouldReturnFalseForUnsupportedClaims(String claimName) {
        assertFalse(ValidClaims.isValidClaim(claimName));
    }
}
