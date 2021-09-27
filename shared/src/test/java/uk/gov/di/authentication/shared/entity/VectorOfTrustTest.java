package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class VectorOfTrustTest {
    @Test
    public void shouldParseValidStringWithSingleVector() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse("Cm", null);
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldParseValidStringWithMultipleVectors() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse("Pa.Cm.Pb", null);
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldParseValidStringAndReturnDefaultIfNoCredentialTrustPresent() {
        VectorOfTrust vectorOfTrust = VectorOfTrust.parse("Pa.Pb", LOW_LEVEL);
        assertThat(vectorOfTrust.getCredentialTrustLevel(), equalTo(LOW_LEVEL));
    }

    @Test
    public void shouldParseThrowOnInvalidString() {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse("Ck", null));
    }
}
