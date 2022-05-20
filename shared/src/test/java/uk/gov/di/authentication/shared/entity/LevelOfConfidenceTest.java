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
import static org.junit.jupiter.api.Assertions.assertThrows;

class LevelOfConfidenceTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LevelOfConfidence.LOW_LEVEL, lessThan(LevelOfConfidence.MEDIUM_LEVEL));
        assertThat(LevelOfConfidence.MEDIUM_LEVEL, lessThan(LevelOfConfidence.HIGH_LEVEL));
        assertThat(LevelOfConfidence.HIGH_LEVEL, lessThan(LevelOfConfidence.VERY_HIGH_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("supportedLevelOfConfidence")
    void shouldReturnLevelOfConfidenceForValidValue(
            String vtrSet, LevelOfConfidence expectedLevel) {
        assertThat(LevelOfConfidence.retrieveLevelOfConfidence(vtrSet), equalTo(expectedLevel));
    }

    @ParameterizedTest
    @MethodSource("unsupportedLevelOfConfidence")
    void shouldThrowWhenUnsupportedValueIsPassed(String vtrSet) {
        assertThrows(
                IllegalArgumentException.class,
                () -> LevelOfConfidence.retrieveLevelOfConfidence(vtrSet));
    }

    @ParameterizedTest
    @MethodSource("invalidLevelOfConfidence")
    void shouldThrowWhenInvalidValueIsPassed(String vtrSet) {
        assertThrows(
                IllegalArgumentException.class,
                () -> LevelOfConfidence.retrieveLevelOfConfidence(vtrSet));
    }

    @Test
    void shouldReturnOnlySupportedLevelOfConfidenceValues() {
        List<String> allLevelOfConfidenceValues =
                LevelOfConfidence.getAllSupportedLevelOfConfidenceValues();

        assertThat(allLevelOfConfidenceValues.size(), equalTo(2));

        assertThat(allLevelOfConfidenceValues.get(0), equalTo(LevelOfConfidence.NONE.getValue()));

        assertThat(
                allLevelOfConfidenceValues.get(1),
                equalTo(LevelOfConfidence.MEDIUM_LEVEL.getValue()));
    }

    private static Stream<Arguments> supportedLevelOfConfidence() {
        return Stream.of(
                Arguments.of("P0", LevelOfConfidence.NONE),
                Arguments.of("P2", LevelOfConfidence.MEDIUM_LEVEL));
    }

    private static Stream<Arguments> unsupportedLevelOfConfidence() {
        return Stream.of(
                Arguments.of("P1", LevelOfConfidence.LOW_LEVEL),
                Arguments.of("P3", LevelOfConfidence.HIGH_LEVEL),
                Arguments.of("P4", LevelOfConfidence.VERY_HIGH_LEVEL));
    }

    private static Stream<Arguments> invalidLevelOfConfidence() {
        return Stream.of(Arguments.of("P2.P1"), Arguments.of("Cl.Cm"), Arguments.of("P2.P3.Cl"));
    }
}
