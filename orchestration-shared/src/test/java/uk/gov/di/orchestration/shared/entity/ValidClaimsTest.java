package uk.gov.di.orchestration.shared.entity;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

// QualityGateUnitTest
class ValidClaimsTest {

    static Stream<String> supportedClaims() {
        return Stream.of(
                "https://vocab.account.gov.uk/v1/address",
                "https://vocab.account.gov.uk/v1/passport",
                "https://vocab.account.gov.uk/v1/coreIdentityJWT",
                "https://vocab.account.gov.uk/v1/drivingPermit",
                "https://vocab.account.gov.uk/v1/returnCode",
                "https://vocab.account.gov.uk/v1/inheritedIdentityJWT");
    }

    static Stream<String> unsupportedClaims() {
        return Stream.of(
                "https://vocab.account.gov.uk/v1/name",
                "https://vocab.account.gov.uk/v1/birthdate",
                "https://vocab.account.gov.uk/v1/socialSecurityRecord");
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnCorrectNumberOfClaimsSupported() {
        MatcherAssert.assertThat(ValidClaims.getAllValidClaims().size(), equalTo(6));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnNamesOfSupportedClaims(String supportedClaim) {
        assertTrue(ValidClaims.getAllValidClaims().contains(supportedClaim));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnTrueForSupportedClaims(String claimName) {
        assertTrue(ValidClaims.isValidClaim(claimName));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("unsupportedClaims")
    void shouldReturnFalseForUnsupportedClaims(String claimName) {
        assertFalse(ValidClaims.isValidClaim(claimName));
    }
}
