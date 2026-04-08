package uk.gov.di.authentication.shared.entity;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class VectorOfTrustTest {

    @Test
    void shouldParseValidStringWithSingleVector() {
        var jsonArray = jsonArrayOf("Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldReturnDefaultVectorWhenEmptyListIsPassedIn() {
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(new ArrayList<>());
        assertThat(
                vectorOfTrust.getCredentialTrustLevel(),
                equalTo(CredentialTrustLevel.getDefault()));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldReturnLowestVectorWhenMultipleSetsAreIsPassedIn() {
        var jsonArray = jsonArrayOf("Cl.Cm", "Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldParseValidStringWithMultipleVectors() {
        var jsonArray = jsonArrayOf("Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldParseValidStringWithSingleIdentityVector() {
        var jsonArray = jsonArrayOf("P2.Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
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
                        "Invalid LevelOfConfidence provided", jsonArrayOf("P2.Cl.Cm", "P4.Cl")),
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
                Arguments.of(MEDIUM_LEVEL, LevelOfConfidence.LOW_LEVEL),
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
                Arguments.of(LOW_LEVEL, LevelOfConfidence.LOW_LEVEL),
                Arguments.of(LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                Arguments.of(null, LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldNotIncludeIdentityValuesInTokenWhenTheyArePresent() {
        String vectorString = "P2.Cl.Cm";

        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo("Cl.Cm"));
    }

    @Test
    void shouldReturnCorrectCredentialTrustLevelInToken() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo(vectorString));
    }

    @Test
    void shouldReturnTrueWhenMediumIdentityLevelOfConfidenceIsPresent() {
        String vectorString = "P2.Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertTrue(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldReturnTrueWhenLowIdentityLevelOfConfidenceIsPresent() {
        String vectorString = "P1.Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertTrue(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsNotPresent() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
    }

    @Test
    void shouldReturnFalseWhenIdentityLevelOfConfidenceIsP0() {
        String vectorString = "P0.Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertFalse(vectorOfTrust.containsLevelOfConfidence());
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
                Arguments.of("[\"P1.Cl.Cm\"]", "[\"Cl.Cm.P1\"]", true),
                Arguments.of("[\"P1.Cl.Cm\"]", "[\"Cl.Cm.P2\"]", false),
                Arguments.of("[\"Cl.Cm\"]", "[\"P2.Cl.Cm\"]", false));
    }
}
