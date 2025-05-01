package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthUserInfoClaimsTest {

    static Stream<String> supportedClaims() {
        return Stream.of(
                "email_verified",
                "salt",
                "local_account_id",
                "current_credential_strength",
                "uplift_required",
                "rp_pairwise_id",
                "phone_number_verified",
                "public_subject_id",
                "legacy_subject_id",
                "phone_number",
                "verified_mfa_method_type",
                "email",
                "new_account",
                "achieved_credential_strength");
    }

    static Stream<String> unsupportedClaims() {
        return Stream.of("unsupported_claim", "another_unsupported_claim");
    }

    @Test
    void shouldReturnCorrectNumberOfClaimsSupported() {
        assertThat(AuthUserInfoClaims.getAllValidClaims().size(), equalTo(14));
    }

    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnNamesOfSupportedClaims(String supportedClaim) {
        assertTrue(AuthUserInfoClaims.getAllValidClaims().contains(supportedClaim));
    }

    @ParameterizedTest
    @MethodSource("supportedClaims")
    void shouldReturnTrueForSupportedClaims(String claimName) {
        assertTrue(AuthUserInfoClaims.isValidClaim(claimName));
    }

    @ParameterizedTest
    @MethodSource("unsupportedClaims")
    void shouldReturnFalseForUnsupportedClaims(String claimName) {
        assertFalse(AuthUserInfoClaims.isValidClaim(claimName));
    }
}
