package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    void shouldParseValidStringWithMultipleIdentityVectors() {
        var jsonArray = jsonArrayOf("Pm.Cl.Cm", "Ph.Cl.Cm", "Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldParseValidStringWithSingleIdentityVector() {
        var jsonArray = jsonArrayOf("Ph.Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.HIGH_LEVEL));
    }

    @Test
    void shouldParseToLowCredentialTrustLevelAndMediumLevelOfConfidence() {
        var jsonArray = jsonArrayOf("Pm.Cl.Cm", "Pm.Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void
            shouldParseToLowCredentialTrustLevelAndMediumLevelOfConfidenceWhenMultipleIdentityLevelsExist() {
        var jsonArray = jsonArrayOf("Pm.Cl.Cm", "Ph.Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(jsonArray));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldThrowWhenIdentityValueIsNotFirstValueInVector() {
        var jsonArray = jsonArrayOf("Cl.Cm.Pm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray)));
    }

    @Test
    void shouldThrowWhenTooManyValuesInVector() {
        var jsonArray = jsonArrayOf("Cl.Cm.Cl");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray)));
    }

    @Test
    void shouldThrowWhenOnlyIdentityLevelIsSentInRequest() {
        var jsonArray = jsonArrayOf("Pm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray)));
    }

    @Test
    void shouldThrowWhenCredentialTrustLevelsAreOrderedIncorrectly() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArrayOf("Pm.Cm.Cl"))));
    }

    @Test
    void shouldThrowWhenMultipleIdentityValuesArePresentInVector() {
        var jsonArray = jsonArrayOf("Pl.Pb");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray)));
    }

    @Test
    void shouldThrowIfOnlyCmIsPresent() {
        var jsonArray = jsonArrayOf("Cm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray)));
    }

    @Test
    void shouldThrowIfEmptyListIsPresent() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList("")));
    }

    @Test
    void shouldReturnCorrectlyFormattedVectorOfTrustForTokenWhenIdentityValuesArePresent() {
        String vectorString = "Pm.Cl.Cm";

        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo(vectorString));
    }

    @Test
    void
            shouldReturnCorrectlyFormattedVectorOfTrustForTokenWhenOnlyCredentialTrustLevelIsPresent() {
        String vectorString = "Cl.Cm";
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf(vectorString)));
        assertThat(vectorOfTrust.retrieveVectorOfTrustForToken(), equalTo(vectorString));
    }
}
