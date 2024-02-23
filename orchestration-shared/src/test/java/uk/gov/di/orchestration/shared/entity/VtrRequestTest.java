package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotVocabVersion;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrRequest;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrSummary;

import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
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
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_NONE;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.VOT_VER_1;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.VOT_VER_2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.VOT_VER_1_2;

public class VtrRequestTest {

    @Test
    void emptyShouldReturnEmptyList() {
        var vtr = VtrRequest.empty();
        assertThat(vtr, is(empty()));
    }

    @Test
    void ofShouldReturnSameElementsAsInput() {
        var vector1 = new VectorOfTrust(C_EMPTY, P_EMPTY);
        var vector2 = new VectorOfTrust(C_LOW, P_EMPTY);
        var vector3 = new VectorOfTrust(C_LOW, P_NONE);
        var vtr = VtrRequest.of(vector1, vector2, vector3);
        assertThat(vtr, containsInAnyOrder(vector1, vector2, vector3));
    }

    @ParameterizedTest
    @MethodSource("parseSuccessTestCases")
    void parseFromAuthRequestAttributeShouldReturnCorrectVtr(List<String> input, List<VectorOfTrust> expected) {
        assertThat(VtrRequest.parseFromAuthRequestAttribute(input), is(equalTo(expected)));
    }

    static Stream<Arguments> parseSuccessTestCases() {
        var vectorEmpty = VectorOfTrust.empty();
        var vectorCl = VectorOfTrust.ofAuthComponent(C_LOW_LEGACY);
        var vectorClCmP0 = new VectorOfTrust(C_MEDIUM_LEGACY, P_NONE);
        var vectorP2C2 = new VectorOfTrust(C_MEDIUM, P_MEDIUM);
        var vectorP2 = VectorOfTrust.ofIdentComponent(P_MEDIUM);
        return Stream.of(
                arguments(null, Collections.emptyList()),
                arguments(Collections.emptyList(), Collections.emptyList()),
                arguments(Collections.singletonList(null), Collections.emptyList()),
                arguments(List.of(""), Collections.emptyList()),
                arguments(List.of("[]"), Collections.emptyList()),
                arguments(List.of("[\"\"]"), List.of(vectorEmpty)),
                arguments(List.of("[\"Cl\",\"\",\"P0.Cl.Cm\"]"), List.of(vectorCl, vectorEmpty, vectorClCmP0)),
                arguments(List.of("[\"P2.C2\",\"P2\"]"), List.of(vectorP2C2, vectorP2)));
    }

    @ParameterizedTest
    @MethodSource("parseFailureTestCases")
    void parseFromAuthRequestAttributeShouldThrowOnBadInput(List<String> input) {
        assertThrows(IllegalArgumentException.class,
                     () -> VtrRequest.parseFromAuthRequestAttribute(input),
                     "Invalid VTR attribute.");
    }

    static Stream<Arguments> parseFailureTestCases() {
        return Stream.of(
                arguments(List.of("UNEXPECTED_TEXT")),
                arguments(List.of("[\"Cl\"]", "[\"\"]")), // non singleton list
                arguments(List.of("[\"R2.D2\"]")), // bad vector
                arguments(List.of("[[\"P2\"]]"))); // wrong nesting
    }

    @ParameterizedTest
    @MethodSource("chooseMinimalSuccessTestCases")
    void chooseMinimalShouldReturnCorrectNormalisedVector(VtrRequest vtrRequest,
                                                          EnumSet<VotVocabVersion> versions,
                                                          VectorOfTrust expectedChosenVectorOfTrust,
                                                          VectorOfTrust expectedEffectiveVectorOfTrust,
                                                          VotVocabVersion expectedVersion) {
        var expectedSummary = new VtrSummary(vtrRequest,
                                             expectedChosenVectorOfTrust,
                                             expectedEffectiveVectorOfTrust,
                                             expectedVersion);
        assertThat(vtrRequest.chooseLevel(versions), equalTo(expectedSummary));
    }

    static Stream<Arguments> chooseMinimalSuccessTestCases() {
        var vectorEmpty = VectorOfTrust.empty();
        var vectorC2P0 = new VectorOfTrust(C_MEDIUM, P_NONE);
        var vectorClCmP0 = new VectorOfTrust(C_MEDIUM_LEGACY, P_NONE);
        var vectorC1P0 = new VectorOfTrust(C_LOW, P_NONE);
        var vectorClP0 = new VectorOfTrust(C_LOW_LEGACY, P_NONE);
        var vectorP0 = VectorOfTrust.ofIdentComponent(P_NONE);
        var vectorCl = VectorOfTrust.ofAuthComponent(C_LOW_LEGACY);
        var vectorC1 = VectorOfTrust.ofAuthComponent(C_LOW);
        var vectorClCm = VectorOfTrust.ofAuthComponent(C_MEDIUM_LEGACY);
        var vectorC2 = VectorOfTrust.ofAuthComponent(C_MEDIUM);

        return Stream.of(
                arguments(VtrRequest.empty(), VOT_VER_1, vectorEmpty, vectorClCmP0, VotVocabVersion.V1),
                arguments(VtrRequest.empty(), VOT_VER_2, vectorEmpty, vectorC2P0, VotVocabVersion.V2),
                arguments(VtrRequest.empty(), VOT_VER_1_2, vectorEmpty, vectorC2P0, VotVocabVersion.V2),

                arguments(VtrRequest.of(vectorEmpty), VOT_VER_1, vectorEmpty, vectorClCmP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorEmpty), VOT_VER_2, vectorEmpty, vectorC2P0, VotVocabVersion.V2),
                arguments(VtrRequest.of(vectorEmpty), VOT_VER_1_2, vectorEmpty, vectorC2P0, VotVocabVersion.V2),

                arguments(VtrRequest.of(vectorP0), VOT_VER_1, vectorP0, vectorClCmP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorP0), VOT_VER_2, vectorP0, vectorC2P0, VotVocabVersion.V2),
                arguments(VtrRequest.of(vectorP0), VOT_VER_1_2, vectorP0, vectorC2P0, VotVocabVersion.V2),

                arguments(VtrRequest.of(vectorClCm), VOT_VER_1_2, vectorClCm, vectorClCmP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorC2), VOT_VER_1_2, vectorC2, vectorC2P0, VotVocabVersion.V2),
                arguments(VtrRequest.of(vectorClCm), VOT_VER_1, vectorClCm, vectorClCmP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorC2), VOT_VER_2, vectorC2, vectorC2P0, VotVocabVersion.V2),

                arguments(VtrRequest.of(vectorClCm, vectorCl), VOT_VER_1_2, vectorCl, vectorClP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorC2, vectorC1), VOT_VER_1_2, vectorC1, vectorC1P0, VotVocabVersion.V2),
                arguments(VtrRequest.of(vectorClCm, vectorCl), VOT_VER_1, vectorCl, vectorClP0, VotVocabVersion.V1),
                arguments(VtrRequest.of(vectorC2, vectorC1), VOT_VER_2, vectorC1, vectorC1P0, VotVocabVersion.V2));
    }

    @Test
    void shouldThrowWhenTryingToEditContents() {
        var vector1 = new VectorOfTrust(C_MEDIUM_LEGACY, P_MEDIUM);
        var vector2 = VectorOfTrust.empty();

        var vtrRequest = new VtrRequest(new LinkedList<>() {{ add(vector1); }});
        assertThrows(UnsupportedOperationException.class, () -> vtrRequest.add(vector2));
        assertThrows(UnsupportedOperationException.class, () -> vtrRequest.remove(vector1));
    }
}
