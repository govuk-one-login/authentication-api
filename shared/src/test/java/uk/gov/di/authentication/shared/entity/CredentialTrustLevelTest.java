package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class CredentialTrustLevelTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("validCredentialTrustLevelValues")
    void valuesShouldBeParsable(String vtrSet, CredentialTrustLevel expectedValue) {
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(vtrSet), equalTo(expectedValue));
    }

    @ParameterizedTest
    @MethodSource("invalidCredentialTrustLevelValues")
    void shouldThrowWhenInvalidValueIsPassed(String vtrSet) {
        assertThrows(
                IllegalArgumentException.class,
                () -> CredentialTrustLevel.retrieveCredentialTrustLevel(vtrSet),
                "Expected to throw exception");
    }

    private static Stream<Arguments> validCredentialTrustLevelValues() {
        return Stream.of(Arguments.of("Cl", LOW_LEVEL), Arguments.of("Cl.Cm", MEDIUM_LEVEL));
    }

    private static Stream<String> invalidCredentialTrustLevelValues() {
        return Stream.of("Cm", "Cm.Cl", "Cl.Cm.Cl.Cm", "P2.Cl.Cm");
    }
}
