package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityHelperTest {
    @Test
    void shouldReturnFalseWhenVtrListIsNull() {
        assertFalse(IdentityHelper.identityRequired(null, true, true));
    }

    @Test
    void shouldReturnFalseWhenVtrListIsEmpty() {
        assertFalse(IdentityHelper.identityRequired(List.of(), true, true));
    }

    @Test
    void shouldReturnFalseWhenNoLevelOfConfidenceIsPresentInVtrList() {
        var vtr = new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL);

        assertFalse(IdentityHelper.identityRequired(List.of(vtr), true, true));
    }

    @Test
    void shouldReturnFalseWhenP0LevelOfConfidenceIsPresentInVtrList() {
        var vtr = VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE);

        assertFalse(IdentityHelper.identityRequired(List.of(vtr), true, true));
    }

    @Test
    void shouldReturnTrueIfLevelOfConfidenceGreaterThanP0IsPresentInVtrList() {
        var vtr =
                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);

        assertTrue(IdentityHelper.identityRequired(List.of(vtr), true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        var vtr =
                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);

        assertFalse(IdentityHelper.identityRequired(List.of(vtr), true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        var vtr =
                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);

        assertFalse(IdentityHelper.identityRequired(List.of(vtr), false, true));
    }
}
