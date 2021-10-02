package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class CredentialTrustLevelTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
    }

    @Test
    void valuesShouldBeParsable() {
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cl")),
                equalTo(LOW_LEVEL));
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cl.Cm")),
                equalTo(MEDIUM_LEVEL));
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cl", "Cl.Cm")),
                equalTo(LOW_LEVEL));
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cl.Cm", "Cl")),
                equalTo(LOW_LEVEL));
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cm.Cl")),
                equalTo(MEDIUM_LEVEL));
        assertThat(
                CredentialTrustLevel.retrieveCredentialTrustLevel(List.of("Cm.Cl", "Cl")),
                equalTo(LOW_LEVEL));
    }
}
