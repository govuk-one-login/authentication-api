package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class CredentialTrustLevelTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("validCredentialTrustLevelValues")
    void valuesShouldBeParsable(List<String> vtrSet, CredentialTrustLevel expectedValue) {
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(vtrSet), equalTo(expectedValue));
    }

    private static Stream<Arguments> validCredentialTrustLevelValues() {
        return Stream.of(
                Arguments.of(List.of("Cl"), LOW_LEVEL),
                Arguments.of(List.of("Cl.Cm"), MEDIUM_LEVEL),
                Arguments.of(List.of("Cl", "Cl.Cm"), LOW_LEVEL),
                Arguments.of(List.of("Cl.Cm", "Cl"), LOW_LEVEL),
                Arguments.of(List.of("Cm.Cl"), MEDIUM_LEVEL));
    }
}
