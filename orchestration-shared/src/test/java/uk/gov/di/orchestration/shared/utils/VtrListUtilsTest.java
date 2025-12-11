package uk.gov.di.orchestration.shared.utils;

import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

// QualityGateUnitTest
class VtrListUtilsTest {
    // QualityGateRegressionTest
    @Test
    void shouldBuildVtrLocListFromSingleVtr() {
        var vtrList = List.of(vtrWithLoc(LevelOfConfidence.LOW_LEVEL));

        var vtrStringList = VtrListUtils.getVtrLocsAsCommaSeparatedString(vtrList);
        assertThat(vtrStringList, equalTo("P1"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldBuildVtrLocListFromMultipleVtrs() {
        var vtrList =
                List.of(
                        vtrWithLoc(LevelOfConfidence.LOW_LEVEL),
                        vtrWithLoc(LevelOfConfidence.MEDIUM_LEVEL));

        var vtrStringList = VtrListUtils.getVtrLocsAsCommaSeparatedString(vtrList);
        assertThat(vtrStringList, equalTo("P1,P2"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldBuildVtrLocListFromMultipleVtrsOutOfOrder() {
        var vtrList =
                List.of(
                        vtrWithLoc(LevelOfConfidence.MEDIUM_LEVEL),
                        vtrWithLoc(LevelOfConfidence.LOW_LEVEL));

        var vtrStringList = VtrListUtils.getVtrLocsAsCommaSeparatedString(vtrList);
        assertThat(vtrStringList, equalTo("P1,P2"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldBuildEmptyVtrLocListFromEmptyVtrList() {
        var vtrStringList = VtrListUtils.getVtrLocsAsCommaSeparatedString(List.of());
        assertTrue(vtrStringList.isEmpty());
    }

    // QualityGateRegressionTest
    @Test
    void shouldBuildVtrLocListFromVtrListWithNoLocSet() {
        var vtrList = List.of(vtrWithLoc(null));

        var vtrStringList = VtrListUtils.getVtrLocsAsCommaSeparatedString(vtrList);
        assertThat(vtrStringList, equalTo("P0"));
    }

    private static VectorOfTrust vtrWithLoc(LevelOfConfidence loc) {
        return VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, loc);
    }
}
