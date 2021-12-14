package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidClaimsTest {

    static Stream<String> suppportedClaims() {
        return Stream.of("name", "birthdate", "address");
    }

    @Test
    void shouldReturnCorrectNumberOfClaimsSupported() {
        assertThat(ValidClaims.getAllowedClaimNames().size(), equalTo(3));
    }

    @ParameterizedTest
    @MethodSource("suppportedClaims")
    void shouldReturnNamesOfSupportedClaims(String supportedClaim) {
        assertTrue(ValidClaims.getAllowedClaimNames().contains(supportedClaim));
    }
}
