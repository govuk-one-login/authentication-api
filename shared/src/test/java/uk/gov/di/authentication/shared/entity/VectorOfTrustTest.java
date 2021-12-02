package uk.gov.di.authentication.shared.entity;

import net.minidev.json.JSONArray;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class VectorOfTrustTest {
    @Test
    void shouldParseValidStringWithSingleVector() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
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
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm");
        jsonArray.add("Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldParseValidStringWithMultipleVectors() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertNull(vectorOfTrust.getLevelOfConfidence());
    }

    @Test
    void shouldParseValidStringWithMultipleIdentityVectors() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pm.Cl.Cm");
        jsonArray.add("Ph.Cl.Cm");
        jsonArray.add("Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldParseValidStringWithSingleIdentityVector() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Ph.Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.HIGH_LEVEL));
    }

    @Test
    void shouldParseToLowCredentialTrustLevelAndMediumLevelOfConfidence() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pm.Cl.Cm");
        jsonArray.add("Pm.Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void
            shouldParseToLowCredentialTrustLevelAndMediumLevelOfConfidenceWhenMultipleIdentityLevelsExist() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pm.Cl.Cm");
        jsonArray.add("Ph.Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldThrowWhenIdentityValueIsNotFirstValueInVector() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm.Pm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    void shouldThrowWhenOnlyIdentityLevelIsSentInRequest() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    void shouldParseVectorWhenCredentialTrustLevelsAreOrderedDifferently() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pm.Cm.Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
        assertThat(vectorOfTrust.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
    }

    @Test
    void shouldParseValidStringAndReThrowIfInvalidValueIsPresent() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pl.Pb");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    void shouldThrowIfOnlyCmIsPresent() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    void shouldThrowIfEmptyListIsPresent() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList("")));
    }
}
