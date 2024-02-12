package uk.gov.di.orchestration.shared.entity;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class VectorOfTrustTest {

    @Test
    void shouldParseValidStringWithSingleVector() {
        var jsonArray = jsonArrayOf("Cl.Cm");
        List<VectorOfTrust> vectorsOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorsOfTrust.get(0).getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertNull(vectorsOfTrust.get(0).getLevelOfConfidence());
        assertThat(vectorsOfTrust.size(), equalTo(1));
    }

    @Test
    void shouldReturnDefaultVectorWhenEmptyListIsPassedIn() {
        List<VectorOfTrust> vectorsOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(new ArrayList<>());
        MatcherAssert.assertThat(
                vectorsOfTrust.get(0).getCredentialTrustLevel(),
                equalTo(CredentialTrustLevel.getDefault()));
        assertNull(vectorsOfTrust.get(0).getLevelOfConfidence());
    }

    @Test
    void shouldParseValidStringWithSingleIdentityVector() {
        var jsonArray = jsonArrayOf("P2.Cl.Cm");
        List<VectorOfTrust> vectorsOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorsOfTrust.get(0).getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(
                vectorsOfTrust.get(0).getLevelOfConfidence(),
                equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldReturnOnlyLevelsOfConfidenceWhenRequested() {
        var vtrList =
                List.of(
                        VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                        VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL));
        var levelsOfConfidence = VectorOfTrust.getRequestedLevelsOfConfidence(vtrList);
        assertThat(levelsOfConfidence, equalTo(List.of("P2", "P1")));
    }

    @ParameterizedTest
    @MethodSource("vtrListsWithLowestCredentialTrustVtrs")
    void shouldReturnCredentialTrustLevelOfLowestVot(
            List<VectorOfTrust> vtrList, CredentialTrustLevel expected) {
        var lowestCredentialLevel = VectorOfTrust.getLowestCredentialTrustLevel(vtrList);
        assertThat(lowestCredentialLevel, equalTo(expected));
    }

    private static Stream<Arguments> vtrListsWithLowestCredentialTrustVtrs() {
        return Stream.of(
                Arguments.of(
                        List.of(
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        LOW_LEVEL),
                Arguments.of(
                        List.of(
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(MEDIUM_LEVEL, null)),
                        MEDIUM_LEVEL),
                Arguments.of(
                        List.of(VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.NONE)), LOW_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("vtrListsToOrder")
    void shouldOrderVtrListsBasedOnLocThenCtl(
            List<VectorOfTrust> vtrList, List<VectorOfTrust> expected) {
        var orderedList = VectorOfTrust.orderVtrList(vtrList);
        assertThat(orderedList, equalTo(expected));
    }

    private static Stream<Arguments> vtrListsToOrder() {
        return Stream.of(
                Arguments.of(
                        List.of(
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        List.of(
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL))),
                Arguments.of(
                        List.of(
                                VectorOfTrust.of(MEDIUM_LEVEL, null),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL)),
                        List.of(
                                VectorOfTrust.of(MEDIUM_LEVEL, null),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL))),
                Arguments.of(
                        List.of(
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.NONE)),
                        List.of(
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.NONE),
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL))));
    }

    @ParameterizedTest
    @MethodSource("invalidVtrValues")
    void shouldThrowWhenInvalidVtrPassed(String errorMessage, String jsonArray) {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                VectorOfTrust.parseFromAuthRequestAttribute(
                                        Collections.singletonList(jsonArray)));
        assertThat(exception.getMessage(), equalTo(errorMessage));
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

    @ParameterizedTest
    @MethodSource("validCombinations")
    void isValidShouldReturnTrueForValidCombinations(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        var vectorOfTrust = VectorOfTrust.of(credentialTrustLevel, levelOfConfidence);

        assertTrue(vectorOfTrust.isValid());
    }

    public static Stream<Arguments> validCombinations() {
        return Stream.of(
                Arguments.of(LOW_LEVEL, null),
                Arguments.of(MEDIUM_LEVEL, null),
                Arguments.of(LOW_LEVEL, LevelOfConfidence.NONE),
                Arguments.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("invalidCombinations")
    void isValidShouldReturnFalseForInvalidCombinations(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        var vectorOfTrust = VectorOfTrust.of(credentialTrustLevel, levelOfConfidence);

        assertFalse(vectorOfTrust.isValid());
    }

    public static Stream<Arguments> invalidCombinations() {
        return Stream.of(
                Arguments.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                Arguments.of(null, LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldNotIncludeIdentityValuesInTokenWhenTheyArePresent() {
        String vectorString = "P2.Cl.Cm";

        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo("Cl.Cm"));
    }

    @Test
    void shouldReturnCorrectCredentialTrustLevelInToken() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo(vectorString));
    }

    @Test
    void shouldReturnTrueWhenIdentityLevelOfConfidenceIsPresent() {
        String vectorString = "P2.Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertTrue(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsNotPresent() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsP0() {
        String vectorString = "P0.Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf(vectorString)))
                        .get(0);
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldThrowExceptionForEmptyVtrList() {
        List<VectorOfTrust> vtrList = Collections.emptyList();

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> VectorOfTrust.getLowestCredentialTrustLevel(vtrList));

        assertEquals("Invalid VTR attribute", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("equalityTests")
    void shouldReturnCorrectEquality(String one, String two, boolean areEqual) {
        var vtrOne = VectorOfTrust.parseFromAuthRequestAttribute(List.of(one));
        var vtrTwo = VectorOfTrust.parseFromAuthRequestAttribute(List.of(two));

        assertThat(vtrOne.equals(vtrTwo), equalTo(areEqual));
    }

    public static Stream<Arguments> equalityTests() {
        return Stream.of(
                Arguments.of("[\"P2.Cl.Cm\"]", "[\"Cl.Cm.P2\"]", true),
                Arguments.of("[\"P2.Cm.Cl\"]", "[\"Cl.Cm.P2\"]", true),
                Arguments.of("[\"Cm.Cl\"]", "[\"Cl.Cm\"]", true),
                Arguments.of("[\"Cl.Cm\"]", "[\"Cl.Cm.P2\"]", false),
                Arguments.of("[\"Cl.Cm\"]", "[\"P2.Cl.Cm\"]", false));
    }
}
