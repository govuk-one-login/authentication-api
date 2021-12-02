package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.HIGH_LEVEL;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.VERY_HIGH_LEVEL;

class LevelOfConfidenceTest {

    @ParameterizedTest
    @MethodSource("validLevelOfConfidence")
    void shouldReturnLevelOfConfidenceForValidValue(
            String vtrSet, LevelOfConfidence expectedLevel) {
        assertThat(LevelOfConfidence.retrieveLevelOfConfidence(vtrSet), equalTo(expectedLevel));
    }

    @ParameterizedTest
    @MethodSource("invalidLevelOfConfidence")
    void shouldThrowWhenInvalidValueIsPassed(String vtrSet, String message) {
        assertThrows(
                IllegalArgumentException.class,
                () -> LevelOfConfidence.retrieveLevelOfConfidence(vtrSet),
                message);
    }

    private static Stream<Arguments> validLevelOfConfidence() {
        return Stream.of(
                Arguments.of("Pl", LOW_LEVEL),
                Arguments.of("Pm", MEDIUM_LEVEL),
                Arguments.of("Ph", HIGH_LEVEL),
                Arguments.of("Pv", VERY_HIGH_LEVEL));
    }

    private static Stream<Arguments> invalidLevelOfConfidence() {
        return Stream.of(
                Arguments.of("Cl.Pl", "Should throw when LevelOfConfidence is not first in String"),
                Arguments.of(
                        "Cl.Cm", "Should throw when no LevelOfConfidence is included in String"),
                Arguments.of(
                        "Pm.Ph.Cl",
                        "Should throw when multiple LevelOfConfidence is included in single String"));
    }
}
