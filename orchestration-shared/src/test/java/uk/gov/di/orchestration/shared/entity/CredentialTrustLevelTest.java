package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.IdentId;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

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

    public static class IdentityIdTest {

        @ParameterizedTest
        @MethodSource("toStringTestCases")
        public void toStringShouldReturnCorrectStringValue(IdentId input, String expected) {
            assertThat(input.toString(), is(equalTo(expected)));
        }

        public static Stream<Arguments> toStringTestCases() {
            return Stream.of(
                    arguments(IdentId.P0, "P0"),
                    arguments(IdentId.P1, "P1"),
                    arguments(IdentId.P2, "P2"),
                    arguments(IdentId.P3, "P3"),
                    arguments(IdentId.P4, "P4"),
                    arguments(IdentId.PCL200, "PCL200"),
                    arguments(IdentId.PCL250, "PCL250"));
        }
    }
}
