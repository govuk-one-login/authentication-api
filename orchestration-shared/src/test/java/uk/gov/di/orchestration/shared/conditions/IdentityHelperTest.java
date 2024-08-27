package uk.gov.di.orchestration.shared.conditions;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.VtrList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityHelperTest {

    @Test
    void shouldReturnFalseWhenVtrNotPresentInAuthRequest() {
        var vtr =
                VtrList.of(
                        new VectorOfTrust(
                                CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE));

        Assertions.assertFalse(IdentityHelper.identityRequired(vtr, true, true));
    }

    @Test
    void shouldReturnFalseWhenP0LevelOfConfidenceIsPresentInAuthRequest() {
        var vtr =
                VtrList.of(
                        new VectorOfTrust(
                                CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE));

        assertFalse(IdentityHelper.identityRequired(vtr, true, true));
    }

    @Test
    void shouldReturnTrueIfLevelOfConfidenceGreaterThanP0IsPresentInAuthRequest() {
        var vtr =
                VtrList.of(
                        new VectorOfTrust(
                                CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));

        assertTrue(IdentityHelper.identityRequired(vtr, true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        var vtr =
                VtrList.of(
                        new VectorOfTrust(
                                CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));

        assertFalse(IdentityHelper.identityRequired(vtr, true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        var vtr =
                VtrList.of(
                        new VectorOfTrust(
                                CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));

        assertFalse(IdentityHelper.identityRequired(vtr, false, true));
    }
}
