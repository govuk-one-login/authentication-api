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
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotVocabVersion;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrRequest;

import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_LOW_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_MEDIUM_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_NONE;

class VectorOfTrustTestOld {

    @Test
    void shouldParseValidStringWithSingleVector() {
        var jsonArray = jsonArrayOf("Cl.Cm");
        VtrRequest vtrList = VtrRequest.parseFromAuthRequestAttribute(List.of(jsonArray));
        assertThat(
                vtrList.get(0).authComponent(),
                equalTo(VectorOfTrust.ofAuthComponent(C_MEDIUM_LEGACY)));
        assertThat(vtrList.get(0).identComponent(), is(empty()));
        assertThat(vtrList.size(), equalTo(1));
    }

    /*@Test
    void shouldReturnDefaultVectorWhenEmptyListIsPassedIn() {
        VtrRequest vtrList = VtrRequest.parseFromAuthRequestAttribute(List.of(""));
        var vector = vtrList.chooseMinimal(EnumSet.of(VotVocabVersion.V1));
        MatcherAssert.assertThat(
                vector.credentialComponent(), equalTo(C_MEDIUM_LEGACY));
        assertThat(vector.identityComponent(), is(equalTo(P_NONE)));
    }*/

    @Test
    void shouldParseValidStringWithSingleIdentityVector() {
        var jsonArray = jsonArrayOf("P2.Cl.Cm");
        VtrRequest vtrList = VtrRequest.parseFromAuthRequestAttribute(List.of(jsonArray));
        assertThat(vtrList.get(0).authComponent(), equalTo(C_MEDIUM_LEGACY));
        assertThat(vtrList.get(0).identComponent(), equalTo(P_MEDIUM));
    }

    @Test
    void shouldReturnOnlyLevelsOfConfidenceWhenRequested() {
        var vtrList =
                VtrRequest.of(
                        new VectorOfTrust(C_LOW_LEGACY, P_MEDIUM),
                        new VectorOfTrust(C_LOW_LEGACY, P_NONE));
        var levelsOfConfidence = vtrList.stream().map(VectorOfTrust::identComponent).toList();
        assertThat(levelsOfConfidence, equalTo(List.of("P2", "P0")));
    }

    /*@ParameterizedTest
    @MethodSource("vtrListsWithLowestCredentialTrustVtrs")
    void shouldReturnCredentialTrustLevelOfLowestVot(
            List<VectorOfTrustLegacy> vtrList, CredentialTrustLevel expected) {
        var lowestCredentialLevel = VectorOfTrustLegacy.getLowestCredentialTrustLevel(vtrList);
        assertThat(lowestCredentialLevel, equalTo(expected));
    }

    private static Stream<Arguments> vtrListsWithLowestCredentialTrustVtrs() {
        return Stream.of(
                Arguments.of(
                        List.of(
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        LOW_LEVEL),
                Arguments.of(
                        List.of(
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, null)),
                        MEDIUM_LEVEL),
                Arguments.of(
                        List.of(VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.NONE)), LOW_LEVEL));
    }*/

    /*@ParameterizedTest
    @MethodSource("vtrListsToOrder")
    void shouldOrderVtrListsBasedOnLocThenCtl(
            List<VectorOfTrustLegacy> vtrList, List<VectorOfTrustLegacy> expected) {
        var orderedList = VectorOfTrustLegacy.orderVtrList(vtrList);
        assertThat(orderedList, equalTo(expected));
    }

    private static Stream<Arguments> vtrListsToOrder() {
        return Stream.of(
                Arguments.of(
                        List.of(
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        List.of(
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL))),
                Arguments.of(
                        List.of(
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, null),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        List.of(
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, null),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL))),
                Arguments.of(
                        List.of(
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.NONE)),
                        List.of(
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.NONE),
                                VectorOfTrustLegacy.of(MEDIUM_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrustLegacy.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL))));
    }*/

    @ParameterizedTest
    @MethodSource("invalidVtrValues")
    void shouldThrowWhenInvalidVtrPassed(String errorMessage, String jsonArray) {
        assertThrows(Exception.class, () -> VtrRequest.parseFromAuthRequestAttribute(List.of(jsonArray)));
        // assertThat(exception.getMessage(), equalTo(errorMessage));
    }

    private static Stream<Arguments> invalidVtrValues() {
        return Stream.of(
                Arguments.of(
                        "VTR must contain either 0 or 1 identity proofing components",
                        jsonArrayOf("P2.P0")),
                Arguments.of("Invalid CredentialTrustLevel", jsonArrayOf("Cm")),
                Arguments.of("Invalid CredentialTrustLevel", jsonArrayOf("P2")),
                Arguments.of("Invalid CredentialTrustLevel", jsonArrayOf("Cl.Cm.Cl")),
                Arguments.of(
                        "Invalid LevelOfConfidence provided", jsonArrayOf("P2.Cl.Cm", "P3.Cl")),
                Arguments.of("Invalid CredentialTrustLevel", jsonArrayOf("Cm")),
                Arguments.of("Invalid CredentialTrustLevel", jsonArrayOf("")),
                Arguments.of(
                        "P2 identity confidence must require at least Cl.Cm credential trust",
                        jsonArrayOf("P2.Cl")));
    }

    /*@ParameterizedTest
    @MethodSource("validCombinations")
    void isValidShouldReturnTrueForValidCombinations(
            VotComponent<AuthId> credentialTrustLevel,
            VotComponent<IdentId> levelOfConfidence) {
        var vectorOfTrust = new VectorOfTrust(credentialTrustLevel, levelOfConfidence);

        assertTrue(VotVocabVersion.V1.validateVector(vectorOfTrust));
    }

    public static Stream<Arguments> validCombinations() {
        return Stream.of(
                Arguments.of(C_LOW_LEGACY, P_EMPTY),
                Arguments.of(C_MEDIUM_LEGACY, P_EMPTY),
                Arguments.of(C_LOW_LEGACY, P_NONE),
                Arguments.of(C_MEDIUM_LEGACY, P_MEDIUM));
    }*/

    /*@ParameterizedTest
    @MethodSource("invalidCombinations")
    void isValidShouldReturnFalseForInvalidCombinations(
            VotComponent<AuthId> credentialTrustLevel,
            VotComponent<IdentId> levelOfConfidence) {
        var vectorOfTrust = new VectorOfTrust(credentialTrustLevel, levelOfConfidence);

        assertFalse(VotVocabVersion.V1.validateVector(vectorOfTrust));
    }*/

    public static Stream<Arguments> invalidCombinations() {
        return Stream.of(
                Arguments.of(C_LOW_LEGACY, P_MEDIUM),
                Arguments.of(C_EMPTY, P_MEDIUM));
    }

    @Test
    void shouldNotIncludeIdentityValuesInTokenWhenTheyArePresent() {
        String vectorString = "P2.Cl.Cm";

        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(vectorString);

        assertThat(vectorOfTrust.authComponent().toString(), equalTo("Cl.Cm"));
    }

    @Test
    void shouldReturnCorrectCredentialTrustLevelInToken() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(vectorString);
        assertThat(vectorOfTrust.authComponent().toString(), equalTo(vectorString));
    }

    /*
    @Test
    void shouldReturnTrueWhenIdentityLevelOfConfidenceIsPresent() {
        String vectorString = "P2.Cl.Cm";
        VectorOfTrustLegacy vectorOfTrust =
                VectorOfTrustLegacy.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertTrue(vectorOfTrust.containsLevelOfConfidence());
    }*/

    /*
    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsNotPresent() {
        String vectorString = "Cl.Cm";
        VectorOfTrustLegacy vectorOfTrust =
                VectorOfTrustLegacy.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
    }*/

    /*
    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsP0() {
        String vectorString = "P0.Cl.Cm";
        VectorOfTrustLegacy vectorOfTrust =
                VectorOfTrustLegacy.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
    }*/

    /*
    @Test
    void shouldThrowExceptionForEmptyVtrList() {
        List<VectorOfTrustLegacy> vtrList = Collections.emptyList();

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> VectorOfTrustLegacy.getLowestCredentialTrustLevel(vtrList));

        assertEquals("Invalid VTR attribute", exception.getMessage());
    }*/

    /*
    @ParameterizedTest
    @MethodSource("equalityTests")
    void shouldReturnCorrectEquality(String one, String two, boolean areEqual) {
        var vtrOne = VectorOfTrustLegacy.parseFromAuthRequestAttribute(List.of(one));
        var vtrTwo = VectorOfTrustLegacy.parseFromAuthRequestAttribute(List.of(two));

        assertThat(vtrOne.equals(vtrTwo), equalTo(areEqual));
    }

    public static Stream<Arguments> equalityTests() {
        return Stream.of(
                Arguments.of("[\"P2.Cl.Cm\"]", "[\"Cl.Cm.P2\"]", true),
                Arguments.of("[\"P2.Cm.Cl\"]", "[\"Cl.Cm.P2\"]", true),
                Arguments.of("[\"Cm.Cl\"]", "[\"Cl.Cm\"]", true),
                Arguments.of("[\"Cl.Cm\"]", "[\"Cl.Cm.P2\"]", false),
                Arguments.of("[\"Cl.Cm\"]", "[\"P2.Cl.Cm\"]", false));
    }*/
}
