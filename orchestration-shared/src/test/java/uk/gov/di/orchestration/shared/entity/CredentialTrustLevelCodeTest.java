package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C1;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL_CM;

public class CredentialTrustLevelCodeTest {

    @ParameterizedTest
    @MethodSource("parseTestCases")
    void parseShouldReturnCorrectCode(String code, CredentialTrustLevelCode expected) {
        assertThat(CredentialTrustLevelCode.parse(code), is(equalTo(expected)));
    }

    static Stream<Arguments> parseTestCases() {
        return Stream.of(
                arguments("Cl", CL),
                arguments("Cl.Cm", CL_CM),
                arguments("Cm.Cl", CL_CM),
                arguments("C2", C2));
    }

    @Test
    void parseShouldThrowOnInvalidString() {
        assertThrows(IllegalArgumentException.class, () -> CredentialTrustLevelCode.parse("P2"));
    }

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectlyFormattedString(
            CredentialTrustLevelCode code, String expected) {
        assertThat(code.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(arguments(CL, "Cl"), arguments(CL_CM, "Cl.Cm"), arguments(C2, "C2"));
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeTestCases")
    <E extends Enum<E>> void equalsAndHashCodeShouldBehaveCorrectly(
            CredentialTrustLevelCode code1, CredentialTrustLevelCode code2, boolean areEqual) {
        assertThat(code1.equals(code2), is(equalTo(areEqual)));
        assertThat(code2.equals(code1), is(equalTo(areEqual)));

        if (areEqual) {
            assertThat(code1.hashCode(), is(equalTo(code2.hashCode())));
        }
    }

    static Stream<Arguments> equalsAndHashCodeTestCases() {
        return Stream.of(
                arguments(CL, CL, true),
                arguments(CL_CM, CL_CM, true),
                arguments(C1, C1, true),
                arguments(C2, C2, true),
                arguments(C2, CL_CM, false),
                arguments(CL, CL_CM, false));
    }
}
