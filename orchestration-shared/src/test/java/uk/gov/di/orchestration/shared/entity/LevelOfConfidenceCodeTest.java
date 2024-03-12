package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P0;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.PCL200;

public class LevelOfConfidenceCodeTest {

    @ParameterizedTest
    @MethodSource("parseTestCases")
    void parseShouldReturnCorrectCode(String code, LevelOfConfidenceCode expected) {
        assertThat(LevelOfConfidenceCode.parse(code), is(equalTo(expected)));
    }

    static Stream<Arguments> parseTestCases() {
        return Stream.of(arguments("", EMPTY), arguments("P0", P0), arguments("PCL200", PCL200));
    }

    @Test
    void parseShouldThrowOnInvalidString() {
        assertThrows(IllegalArgumentException.class, () -> LevelOfConfidenceCode.parse("Cl.Cm"));
    }

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectlyFormattedString(LevelOfConfidenceCode code, String expected) {
        assertThat(code.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(arguments(EMPTY, ""), arguments(P0, "P0"), arguments(PCL200, "PCL200"));
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeTestCases")
    <E extends Enum<E>> void equalsAndHashCodeShouldBehaveCorrectly(
            LevelOfConfidenceCode code1, LevelOfConfidenceCode code2, boolean areEqual) {
        assertThat(code1.equals(code2), is(equalTo(areEqual)));
        assertThat(code2.equals(code1), is(equalTo(areEqual)));

        if (areEqual) {
            assertThat(code1.hashCode(), is(equalTo(code2.hashCode())));
        }
    }

    static Stream<Arguments> equalsAndHashCodeTestCases() {
        return Stream.of(
                arguments(EMPTY, EMPTY, true),
                arguments(P0, P0, true),
                arguments(P2, P2, true),
                arguments(PCL200, PCL200, true),
                arguments(EMPTY, P0, false),
                arguments(PCL200, P2, false));
    }
}
