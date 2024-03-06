package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelId;

import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CredentialTrustLevelIdTest {

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectStringValue(CredentialTrustLevelId input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(CredentialTrustLevelId.CL, "Cl"),
                arguments(CredentialTrustLevelId.CM, "Cm"),
                arguments(CredentialTrustLevelId.C1, "C1"),
                arguments(CredentialTrustLevelId.C2, "C2"),
                arguments(CredentialTrustLevelId.C3, "C3"),
                arguments(CredentialTrustLevelId.C4, "C4"));
    }

    @ParameterizedTest
    @MethodSource("tryParseTestCases")
    void tryParseShouldReturnCorrectValue(String input, Optional<CredentialTrustLevelId> expected) {
        assertThat(CredentialTrustLevelId.tryParse(input), is(equalTo(expected)));
    }

    static Stream<Arguments> tryParseTestCases() {
        return Stream.of(
                arguments("Cl", Optional.of(CredentialTrustLevelId.CL)),
                arguments("Cm", Optional.of(CredentialTrustLevelId.CM)),
                arguments("C1", Optional.of(CredentialTrustLevelId.C1)),
                arguments("C2", Optional.of(CredentialTrustLevelId.C2)),
                arguments("C3", Optional.of(CredentialTrustLevelId.C3)),
                arguments("C4", Optional.of(CredentialTrustLevelId.C4)),
                arguments("C0", Optional.empty()));
    }
}
