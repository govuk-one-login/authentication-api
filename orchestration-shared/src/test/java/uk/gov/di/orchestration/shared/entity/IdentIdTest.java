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
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class IdentIdTest {

    @Test
    public void test() {

    }

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectStringValue(IdentId input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
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
