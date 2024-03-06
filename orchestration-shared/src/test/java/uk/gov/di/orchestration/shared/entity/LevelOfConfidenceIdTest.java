package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceId;

import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class LevelOfConfidenceIdTest {

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectStringValue(LevelOfConfidenceId input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(LevelOfConfidenceId.P0, "P0"),
                arguments(LevelOfConfidenceId.P1, "P1"),
                arguments(LevelOfConfidenceId.P2, "P2"),
                arguments(LevelOfConfidenceId.P3, "P3"),
                arguments(LevelOfConfidenceId.P4, "P4"),
                arguments(LevelOfConfidenceId.PCL200, "PCL200"),
                arguments(LevelOfConfidenceId.PCL250, "PCL250"));
    }

    @ParameterizedTest
    @MethodSource("tryParseTestCases")
    void tryParseShouldReturnCorrectValue(String input, Optional<LevelOfConfidenceId> expected) {
        assertThat(LevelOfConfidenceId.tryParse(input), is(equalTo(expected)));
    }

    static Stream<Arguments> tryParseTestCases() {
        return Stream.of(
                arguments("P0", Optional.of(LevelOfConfidenceId.P0)),
                arguments("P1", Optional.of(LevelOfConfidenceId.P1)),
                arguments("P2", Optional.of(LevelOfConfidenceId.P2)),
                arguments("P3", Optional.of(LevelOfConfidenceId.P3)),
                arguments("P4", Optional.of(LevelOfConfidenceId.P4)),
                arguments("PCL200", Optional.of(LevelOfConfidenceId.PCL200)),
                arguments("PCL250", Optional.of(LevelOfConfidenceId.PCL250)),
                arguments("PCL520", Optional.empty()));
    }
}
