package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityHelperTest {

    @Test
    void shouldReturnFalseWhenLevelOfConfidenceIsNull() {
        LevelOfConfidence levelOfConfidence = null;

        assertFalse(IdentityHelper.identityRequired(levelOfConfidence, true, true));
    }

    @Test
    void shouldReturnFalseWhenP0LevelOfConfidenceIsPresentInAuthRequest() {
        var levelOfConfidence = LevelOfConfidence.NONE;

        assertFalse(IdentityHelper.identityRequired(levelOfConfidence, true, true));
    }

    @Test
    void shouldReturnTrueIfLevelOfConfidenceGreaterThanP0IsPresentInAuthRequest() {
        var levelOfConfidence = LevelOfConfidence.MEDIUM_LEVEL;

        assertTrue(IdentityHelper.identityRequired(levelOfConfidence, true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        var levelOfConfidence = LevelOfConfidence.MEDIUM_LEVEL;

        assertFalse(IdentityHelper.identityRequired(levelOfConfidence, true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        var levelOfConfidence = LevelOfConfidence.MEDIUM_LEVEL;

        assertFalse(IdentityHelper.identityRequired(levelOfConfidence, false, true));
    }
}
