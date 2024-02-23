package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.AuthId;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class AuthIdTest {

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectStringValue(AuthId input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(AuthId.CL, "Cl"),
                arguments(AuthId.CM, "Cm"),
                arguments(AuthId.C1, "C1"),
                arguments(AuthId.C2, "C2"),
                arguments(AuthId.C3, "C3"),
                arguments(AuthId.C4, "C4"));
    }
}
