package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class VectorOfTrustTest {
    @Test
    public void shouldParseValidStringWithSingleVector() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(List.of("Cl.Cm"));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldReturnDefaultVectorWhenEmptyListIsPassedIn() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(new ArrayList<>());
        assertThat(
                vectorOfTrust.getCredentialTrustLevel(),
                equalTo(CredentialTrustLevel.getDefault()));
    }

    @Test
    public void shouldReturnLowestVectorWhenMultipleSetsAreIsPassedIn() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(List.of("Cl.Cm", "Cl"));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
    }

    @Test
    public void shouldParseValidStringWithMultipleVectors() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse(List.of("Cl"));
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
    }

    @Test
    public void shouldParseValidStringAndReThrowIfInvalidValueIsPresent() {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse(List.of("Pl.Pb")));
    }

    @Test
    public void shouldThrowIfOnlyCmIsPresent() {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse(List.of("Cm")));
    }
}
