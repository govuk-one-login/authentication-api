package uk.gov.di.orchestration.shared.entity;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_LOW_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_MEDIUM_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_HMRC250;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_NONE;

public class VectorOfTrustTest {

    private static VectorOfTrust votEmpty;
    private static VectorOfTrust votCl;
    private static VectorOfTrust votC1;
    private static VectorOfTrust votClCm;
    private static VectorOfTrust votC2;
    private static VectorOfTrust votClP0;
    private static VectorOfTrust votC1P0;
    private static VectorOfTrust votClCmP0;
    private static VectorOfTrust votC2P0;
    private static VectorOfTrust votP0;
    private static VectorOfTrust votP2;
    private static VectorOfTrust votClCmP2;
    private static VectorOfTrust votC2P2;
    private static VectorOfTrust votC2PCL250;

    @BeforeAll
    public static void Setup()
    {
        votEmpty = VectorOfTrust.empty();
        votCl = VectorOfTrust.ofAuthComponent(AUTH_LOW_LEGACY);
        votC1 = VectorOfTrust.ofAuthComponent(AUTH_LOW);
        votClCm = VectorOfTrust.ofAuthComponent(AUTH_MEDIUM_LEGACY);
        votC2 = VectorOfTrust.ofAuthComponent(AUTH_MEDIUM);
        votClP0 = new VectorOfTrust(AUTH_LOW_LEGACY, IDENT_LOW);
        votC1P0 = new VectorOfTrust(AUTH_LOW, IDENT_LOW);
        votClCmP0 = new VectorOfTrust(AUTH_MEDIUM_LEGACY, IDENT_LOW);
        votC2P0 = new VectorOfTrust(AUTH_MEDIUM, IDENT_LOW);
        votP0 = VectorOfTrust.ofIdentComponent(IDENT_NONE);
        votP2 = VectorOfTrust.ofIdentComponent(IDENT_NONE);
        votClCmP2 = new VectorOfTrust(AUTH_MEDIUM_LEGACY, IDENT_MEDIUM);
        votC2P2 = new VectorOfTrust(AUTH_MEDIUM, IDENT_MEDIUM);
        votC2PCL250 = new VectorOfTrust(AUTH_MEDIUM, IDENT_HMRC250);
    }

    @Test
    void emptyShouldReturnAVectorWithEmptyComponents() {
        var vot = VectorOfTrust.empty();
        assertThat(vot.getAuthComponent(), is(empty()));
        assertThat(vot.getIdentComponent(), is(empty()));
    }

    @Test
    void ofAuthComponentShouldReturnAVectorWithOnlyTheGivenCredentialComponent() {
        var vot = VectorOfTrust.ofAuthComponent(AUTH_MEDIUM_LEGACY);
        assertThat(vot.getAuthComponent(), is(equalTo(AUTH_MEDIUM_LEGACY)));
        assertThat(vot.getIdentComponent(), is(empty()));
    }

    @Test
    void ofIdentComponentShouldReturnAVectorWithOnlyTheGivenCredentialComponent() {
        var vot = VectorOfTrust.ofIdentComponent(IDENT_MEDIUM);
        assertThat(vot.getAuthComponent(), is(empty()));
        assertThat(vot.getIdentComponent(), is(equalTo(IDENT_MEDIUM)));
    }

    @ParameterizedTest
    @MethodSource("parseTestCases")
    void parseShouldReturnCorrectVectorOfTrust(String input, VectorOfTrust expectedVot) {
        var actualVot = VectorOfTrust.parse(input);
        MatcherAssert.assertThat(actualVot.getAuthComponent(), is(equalTo(expectedVot.getAuthComponent())));
        MatcherAssert.assertThat(actualVot.getIdentComponent(), is(equalTo(expectedVot.getIdentComponent())));
    }

    static Stream<Arguments> parseTestCases() {
        return Stream.of(
                arguments("", votEmpty),
                arguments("Cl", votCl),
                arguments("Cl.Cm", votClCm),
                arguments("P0", votP0),
                arguments("Cl.Cm.P2", votClCmP2),
                arguments("Cm.P2.Cl", votClCmP2), // note we support arbitrary ordering if ids
                arguments("PCL250.C2", votC2PCL250)
        );
    }

    @ParameterizedTest
    @MethodSource("throwUnknownIdTestCases")
    void parseShouldThrowWhenUnknownIdIsProvided(String invalid) {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse(invalid));
    }

    static Stream<Arguments> throwUnknownIdTestCases() {
        return Stream.of(
                arguments(" "), // unexpected whitespace
                arguments(" Cl"), // ...
                arguments("Cl "), // ...
                arguments("CL"), // wrong case
                arguments("ClCm"), // bad formatting
                arguments("Cl Cm"), // ...
                arguments("Cl..P0"), // ...
                arguments("."), // ...
                arguments(".P0"), // ...
                arguments("P0."), // ...
                arguments("Clm"), // bad id
                arguments("HMRC200")); // ...
    }

    @ParameterizedTest
    @MethodSource("getNormalisedTestCases")
    public void getNormalisedShouldReturnNormalisedVot(VectorOfTrust vot, VectorOfTrust expectedNormaliseVot) {
        var actualNormalisedVot = vot.getNormalised();
        assertThat(actualNormalisedVot.getAuthComponent(), is(equalTo(expectedNormaliseVot)));
        assertThat(actualNormalisedVot.getIdentComponent(), is(equalTo(expectedNormaliseVot.getIdentComponent())));
        assertThat(actualNormalisedVot.getNormalised() == actualNormalisedVot, is(true));
    }

    static Stream<Arguments> getNormalisedTestCases() {
        return Stream.of(
                // equivalent group 1
                arguments(votCl, votClP0),
                arguments(votC1, votClP0),
                arguments(votClP0, votClP0),
                arguments(votC1P0, votClP0),
                // equivalent group 2
                arguments(votEmpty, votClCmP0),
                arguments(votP0, votClCmP0),
                arguments(votClCm, votClCmP0),
                arguments(votC2, votClCmP0),
                arguments(votClCmP0, votClCmP0),
                arguments(votC2P0, votClCmP0),
                // equivalent group 3
                arguments(votP2, votClCmP2),
                arguments(votClCmP2, votClCmP2),
                arguments(votC2P2, votClCmP2)
        );
    }

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    public void toStringShouldReturnCorrectStringValue(VectorOfTrust input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(votEmpty, ""),
                arguments(votCl, "Cl"),
                arguments(votClCm, "Cl.Cm"),
                arguments(votP0, "P0"),
                arguments(votClCmP2, "Cl.Cm.P2"),
                arguments(votC2PCL250, "C2.PCL250")
        );
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeAnCompareToTestCases")
    void equalsAndHashCodeAndCompareToShouldBehaveCorrectly(VectorOfTrust vot1,
                                                            VectorOfTrust vot2,
                                                            int expectedCompareToSignum) {
        // test compareTo
        assertThat(Math.signum(vot1.compareTo(vot2)), is(equalTo(expectedCompareToSignum)));
        assertThat(Math.signum(vot2.compareTo(vot1)), is(equalTo(-expectedCompareToSignum)));

        var expectedEquals = expectedCompareToSignum == 0;

        // test equals
        assertThat(vot1.equals(vot2), is(equalTo(expectedEquals)));
        assertThat(vot2.equals(vot1), is(equalTo(expectedEquals)));

        if (expectedEquals) {
            // test hashCode
            assertThat(vot1.hashCode(), is(equalTo(vot2.hashCode())));
        }
    }

    static Stream<Arguments> equalsAndHashCodeAnCompareToTestCases() {
        return Stream.of(
                // equivalent group 1
                arguments(votCl, votC1, 0),
                arguments(votCl, votClP0, 0),
                arguments(votCl, votC1P0, 0),
                // equivalent group 2
                arguments(votEmpty, votP0, 0),
                arguments(votEmpty, votClCm, 0),
                arguments(votEmpty, votC2, 0),
                arguments(votEmpty, votClCmP0, 0),
                arguments(votEmpty, votC2P0, 0),
                // equivalent group 3
                arguments(votP2, votClCmP2, 0),
                arguments(votP2, votC2P2, 0),
                // different
                arguments(votC1P0, votC2P0, -1),
                arguments(votC2P2, votC2P0, 1),
                arguments(votC1P0, votC2P2, -1)
        );
    }
}
