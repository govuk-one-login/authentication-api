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

class LevelOfConfidenceTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LevelOfConfidence.LOW_LEVEL, lessThan(LevelOfConfidence.MEDIUM_LEVEL));
        assertThat(LevelOfConfidence.MEDIUM_LEVEL, lessThan(LevelOfConfidence.HIGH_LEVEL));
        assertThat(LevelOfConfidence.HIGH_LEVEL, lessThan(LevelOfConfidence.VERY_HIGH_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("validLevelOfConfidence")
    void shouldReturnLevelOfConfidenceForValidValue(
            String vtrSet, LevelOfConfidence expectedLevel) {
        assertThat(LevelOfConfidence.retrieveLevelOfConfidence(vtrSet), equalTo(expectedLevel));
    }

    @ParameterizedTest
    @MethodSource("invalidLevelOfConfidence")
    void shouldThrowWhenInvalidValueIsPassed(String vtrSet) {
        assertThrows(
                IllegalArgumentException.class,
                () -> LevelOfConfidence.retrieveLevelOfConfidence(vtrSet));
    }

    private static Stream<Arguments> validLevelOfConfidence() {
        return Stream.of(
                Arguments.of("Pl", LevelOfConfidence.LOW_LEVEL),
                Arguments.of("Pm", LevelOfConfidence.MEDIUM_LEVEL),
                Arguments.of("Ph", LevelOfConfidence.HIGH_LEVEL),
                Arguments.of("Pv", LevelOfConfidence.VERY_HIGH_LEVEL));
    }

    private static Stream<Arguments> invalidLevelOfConfidence() {
        return Stream.of(Arguments.of("Pm.Pl"), Arguments.of("Cl.Cm"), Arguments.of("Pm.Ph.Cl"));
    }
}
