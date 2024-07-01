package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.HMRC200;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.HMRC250;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidenceCode.EMPTY;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidenceCode.P0;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidenceCode.P2;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidenceCode.PCL200;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidenceCode.PCL250;

class LevelOfConfidenceTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(NONE, lessThan(MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("ofSuccessTestCases")
    void ofShouldReturnCorrectValue(LevelOfConfidenceCode code, LevelOfConfidence expectedLoc) {
        assertThat(LevelOfConfidence.of(code), is(equalTo(expectedLoc)));
    }

    static Stream<Arguments> ofSuccessTestCases() {
        return Stream.of(
                arguments(EMPTY, NONE),
                arguments(P0, NONE),
                arguments(PCL200, HMRC200),
                arguments(PCL250, HMRC250),
                arguments(P2, MEDIUM_LEVEL));
    }

    @Test
    void ofShouldThrowIfInvalidCodeProvided() {
        var invalid =
                new LevelOfConfidenceCode(
                        EnumSet.of(LevelOfConfidenceId.P0, LevelOfConfidenceId.PCL200));
        assertThrows(IllegalArgumentException.class, () -> LevelOfConfidence.of(invalid));
    }

    @ParameterizedTest
    @MethodSource("getDefaultCodeTestCases")
    void getDefaultCodeShouldReturnCorrectValue(
            LevelOfConfidence loc, LevelOfConfidenceCode expectedLocCode) {
        assertThat(loc.getDefaultCode(), is(equalTo(expectedLocCode)));
    }

    static Stream<Arguments> getDefaultCodeTestCases() {
        return Stream.of(
                arguments(NONE, P0),
                arguments(HMRC200, PCL200),
                arguments(HMRC250, PCL250),
                arguments(MEDIUM_LEVEL, P2));
    }

    @ParameterizedTest
    @MethodSource("getAllCodesTestCases")
    void getAllCodesShouldReturnCorrectValue(
            LevelOfConfidence loc, Set<LevelOfConfidenceCode> expectedLocCodes) {
        assertThat(loc.getAllCodes(), is(equalTo(expectedLocCodes)));
    }

    static Stream<Arguments> getAllCodesTestCases() {
        return Stream.of(
                arguments(NONE, Set.of(P0, EMPTY)),
                arguments(HMRC200, Set.of(PCL200)),
                arguments(HMRC250, Set.of(PCL250)),
                arguments(MEDIUM_LEVEL, Set.of(P2)));
    }
}
