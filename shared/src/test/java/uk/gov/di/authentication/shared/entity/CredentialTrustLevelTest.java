package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThan;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.HIGH_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.VERY_HIGH_LEVEL;

class CredentialTrustLevelTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
        assertThat(MEDIUM_LEVEL, lessThan(HIGH_LEVEL));
        assertThat(HIGH_LEVEL, lessThan(VERY_HIGH_LEVEL));
    }
}