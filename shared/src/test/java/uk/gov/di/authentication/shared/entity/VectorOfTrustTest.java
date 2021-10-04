package uk.gov.di.authentication.shared.entity;

import net.minidev.json.JSONArray;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class VectorOfTrustTest {
    @Test
    public void shouldParseValidStringWithSingleVector() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldReturnDefaultVectorWhenEmptyListIsPassedIn() {
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(new ArrayList<>());
        assertThat(
                vectorOfTrust.getCredentialTrustLevel(),
                equalTo(CredentialTrustLevel.getDefault()));
    }

    @Test
    public void shouldReturnLowestVectorWhenMultipleSetsAreIsPassedIn() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm");
        jsonArray.add("Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
    }

    @Test
    public void shouldParseValidStringWithMultipleVectors() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl");
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArray.toJSONString()));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
    }

    @Test
    public void shouldParseValidStringAndReThrowIfInvalidValueIsPresent() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Pl.Pb");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    public void shouldThrowIfOnlyCmIsPresent() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cm");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VectorOfTrust.parseFromAuthRequestAttribute(
                                Collections.singletonList(jsonArray.toJSONString())));
    }

    @Test
    public void shouldThrowIfEmptyListIsPresent() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList("")));
    }
}
