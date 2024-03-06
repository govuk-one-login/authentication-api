package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceId;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.HMRC200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.HMRC250;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.NONE;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.VERY_HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P0;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P1;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P3;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P4;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.PCL200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.PCL250;

class LevelOfConfidenceTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
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
                arguments(P1, LOW_LEVEL),
                arguments(P2, MEDIUM_LEVEL),
                arguments(P3, HIGH_LEVEL),
                arguments(P4, VERY_HIGH_LEVEL),
                arguments(PCL200, HMRC200),
                arguments(PCL250, HMRC250));
    }

    @Test
    void ofShouldThrowIfInvalidCodeProvided() {
        var invalid =
                new LevelOfConfidenceCode(
                        EnumSet.of(LevelOfConfidenceId.P1, LevelOfConfidenceId.PCL200));
        assertThrows(IllegalArgumentException.class, () -> LevelOfConfidence.of(invalid));
    }

    @ParameterizedTest
    @MethodSource("getDefaultCodeTestCases")
    void getDefaultCodeShouldReturnCorrectValue(
            LevelOfConfidence loc, LevelOfConfidenceCode expectedIdentComponent) {
        assertThat(loc.getDefaultCode(), is(equalTo(expectedIdentComponent)));
    }

    static Stream<Arguments> getDefaultCodeTestCases() {
        return Stream.of(
                arguments(NONE, P0),
                arguments(LOW_LEVEL, P1),
                arguments(MEDIUM_LEVEL, P2),
                arguments(HIGH_LEVEL, P3),
                arguments(VERY_HIGH_LEVEL, P4),
                arguments(HMRC200, PCL200),
                arguments(HMRC250, PCL250));
    }

    @ParameterizedTest
    @MethodSource("isSupportedTestCases")
    void isSupportedShouldReturnCorrectValue(LevelOfConfidence loc, boolean expectedIsSupported) {
        assertThat(loc.isSupported(), is(equalTo(expectedIsSupported)));
    }

    static Stream<Arguments> isSupportedTestCases() {
        return Stream.of(
                arguments(NONE, true),
                arguments(LOW_LEVEL, false),
                arguments(MEDIUM_LEVEL, true),
                arguments(HIGH_LEVEL, false),
                arguments(VERY_HIGH_LEVEL, false),
                arguments(HMRC200, true),
                arguments(HMRC250, true));
    }

    @ParameterizedTest
    @MethodSource("getKindTestCases")
    void getKindShouldReturnCorrectValue(
            LevelOfConfidence loc, LevelOfConfidence.Kind expectedKind) {
        assertThat(loc.getKind(), is(equalTo(expectedKind)));
    }

    static Stream<Arguments> getKindTestCases() {
        return Stream.of(
                arguments(NONE, LevelOfConfidence.Kind.NONE),
                arguments(LOW_LEVEL, LevelOfConfidence.Kind.STANDARD),
                arguments(MEDIUM_LEVEL, LevelOfConfidence.Kind.STANDARD),
                arguments(HIGH_LEVEL, LevelOfConfidence.Kind.STANDARD),
                arguments(VERY_HIGH_LEVEL, LevelOfConfidence.Kind.STANDARD),
                arguments(HMRC200, LevelOfConfidence.Kind.HMRC),
                arguments(HMRC250, LevelOfConfidence.Kind.HMRC));
    }
}
