package uk.gov.di.orchestration.shared.entity;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.AuthId;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.IdentId;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotComponent;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_LOW_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_MEDIUM_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_HMRC250;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_NONE;

public class VectorOfTrustTest {
    @Test
    void emptyShouldReturnAVectorWithEmptyComponents() {
        var vector = VectorOfTrust.empty();
        assertThat(vector.authComponent(), is(empty()));
        assertThat(vector.identComponent(), is(empty()));
    }

    @Test
    void ofAuthComponentShouldReturnAVectorWithOnlyTheGivenCredentialComponent() {
        var vector = VectorOfTrust.ofAuthComponent(C_MEDIUM_LEGACY);
        assertThat(vector.authComponent(), is(equalTo(C_MEDIUM_LEGACY)));
        assertThat(vector.identComponent(), is(empty()));
    }

    @Test
    void ofIdentComponentShouldReturnAVectorWithOnlyTheGivenCredentialComponent() {
        var vector = VectorOfTrust.ofIdentComponent(P_MEDIUM);
        assertThat(vector.authComponent(), is(empty()));
        assertThat(vector.identComponent(), is(equalTo(P_MEDIUM)));
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeTestCases")
    void equalsAndHashCodeShouldBehaveCorrectly(VectorOfTrust vector1, VectorOfTrust vector2, boolean areEqual) {
        assertThat(vector1.equals(vector2), is(equalTo(areEqual)));
        assertThat(vector2.equals(vector1), is(equalTo(areEqual)));

        if (areEqual) {
            assertThat(vector1.hashCode(), is(equalTo(vector1.hashCode())));
        }
    }

    static Stream<Arguments> equalsAndHashCodeTestCases() {
        var vectorClCmP0A = new VectorOfTrust(C_MEDIUM_LEGACY, P_NONE);
        var vectorClCmP0B = new VectorOfTrust(C_MEDIUM_LEGACY, P_NONE);
        var vectorC1P0A = new VectorOfTrust(C_LOW, P_NONE);
        var vectorC1P0B = new VectorOfTrust(C_LOW, P_NONE);
        var vectorClCmP2A = new VectorOfTrust(C_MEDIUM_LEGACY, P_MEDIUM);
        var vectorClCmP2B = new VectorOfTrust(C_MEDIUM_LEGACY, P_MEDIUM);
        var vectorC1P2A = new VectorOfTrust(C_LOW, P_MEDIUM);
        var vectorC1P2B = new VectorOfTrust(C_LOW, P_MEDIUM);
        var vectorClCmEmptyA = new VectorOfTrust(C_MEDIUM_LEGACY, P_EMPTY);
        var vectorClCmEmptyB = new VectorOfTrust(C_MEDIUM_LEGACY, P_EMPTY);
        var vectorEmptyP0A = new VectorOfTrust(C_EMPTY, P_NONE);
        var vectorEmptyP0B = new VectorOfTrust(C_EMPTY, P_NONE);
        var vectorEmptyEmptyA = new VectorOfTrust(C_EMPTY, P_EMPTY);
        var vectorEmptyEmptyB = new VectorOfTrust(C_EMPTY, P_EMPTY);

        return Stream.of(
                arguments(vectorClCmP0A, vectorClCmP0B, true),
                arguments(vectorC1P0A, vectorC1P0B, true),
                arguments(vectorClCmP2A, vectorClCmP2B, true),
                arguments(vectorC1P2A, vectorC1P2B, true),
                arguments(vectorClCmEmptyA, vectorClCmEmptyB, true),
                arguments(vectorEmptyP0A, vectorEmptyP0B, true),
                arguments(vectorEmptyEmptyA, vectorEmptyEmptyB, true),
                arguments(vectorClCmP0A, vectorC1P0A, false),
                arguments(vectorClCmP0A, vectorClCmP2A, false),
                arguments(vectorClCmP0A, vectorC1P2A, false),
                arguments(vectorClCmP0A, vectorClCmEmptyA, false),
                arguments(vectorClCmP0A, vectorEmptyP0A, false),
                arguments(vectorClCmP0A, vectorEmptyEmptyA, false),
                arguments(vectorC1P0A, vectorClCmP2A, false),
                arguments(vectorC1P0A, vectorC1P2A, false),
                arguments(vectorC1P0A, vectorClCmEmptyA, false),
                arguments(vectorC1P0A, vectorEmptyP0A, false),
                arguments(vectorC1P0A, vectorEmptyEmptyA, false),
                arguments(vectorClCmP2A, vectorC1P2A, false),
                arguments(vectorClCmP2A, vectorClCmEmptyA, false),
                arguments(vectorClCmP2A, vectorEmptyP0A, false),
                arguments(vectorClCmP2A, vectorEmptyEmptyA, false),
                arguments(vectorC1P2A, vectorClCmEmptyA, false),
                arguments(vectorC1P2A, vectorEmptyP0A, false),
                arguments(vectorC1P2A, vectorEmptyEmptyA, false),
                arguments(vectorClCmEmptyA, vectorEmptyP0A, false),
                arguments(vectorClCmEmptyA, vectorEmptyEmptyA, false));
    }

    @ParameterizedTest
    @MethodSource("parseTestCases")
    void parseShouldReturnCorrectVectorOfTrust(String input, VectorOfTrust expected) {
        MatcherAssert.assertThat(VectorOfTrust.parse(input), is(equalTo(expected)));
    }

    static Stream<Arguments> parseTestCases() {
        return Stream.of(
                arguments(
                        "",
                        new VectorOfTrust(
                                VotComponent.empty(AuthId.class),
                                VotComponent.empty(IdentId.class))),
                arguments(
                        "Cl",
                        new VectorOfTrust(
                                VotComponent.of(AuthId.CL),
                                VotComponent.empty(IdentId.class))),
                arguments(
                        "Cl.Cm",
                        new VectorOfTrust(
                                VotComponent.of(AuthId.CL, AuthId.CM),
                                VotComponent.empty(IdentId.class))),
                arguments(
                        "P0",
                        new VectorOfTrust(
                                VotComponent.empty(AuthId.class),
                                VotComponent.of(IdentId.P0))),
                arguments(
                        "Cl.Cm.P2",
                        new VectorOfTrust(
                                VotComponent.of(AuthId.CL, AuthId.CM),
                                VotComponent.of(IdentId.P2))),
                arguments(
                        "Cm.P2.Cl",
                        new VectorOfTrust(
                                VotComponent.of(AuthId.CL, AuthId.CM),
                                VotComponent.of(IdentId.P2))),
                arguments(
                        "PCL250.C2",
                        new VectorOfTrust(
                                VotComponent.of(AuthId.C2),
                                VotComponent.of(IdentId.PCL250))));
    }

    @ParameterizedTest
    @MethodSource("throwUnknownId")
    void parseShouldThrowWhenUnknownIdIsProvided(String invalid) {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse(invalid));
    }

    static Stream<Arguments> throwUnknownId() {
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
    @MethodSource("toStringTestCases")
    public void toStringShouldReturnCorrectStringValue(VectorOfTrust input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(new VectorOfTrust(C_EMPTY, P_EMPTY), ""),
                arguments(new VectorOfTrust(C_LOW_LEGACY, P_EMPTY), "Cl"),
                arguments(new VectorOfTrust(C_MEDIUM_LEGACY, P_EMPTY), "Cl.Cm"),
                arguments(new VectorOfTrust(C_EMPTY, P_NONE), "P0"),
                arguments(new VectorOfTrust(C_MEDIUM_LEGACY, P_MEDIUM), "Cl.Cm.P2"),
                arguments(new VectorOfTrust(C_MEDIUM, P_HMRC250), "C2.PCL250"));
    }
}
