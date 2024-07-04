package uk.gov.di.orchestration.shared.conditions;

import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.List;

import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

public class MfaHelper {

    private MfaHelper() {}

    public static boolean mfaRequired(List<VectorOfTrust> vtrList) {
        return vtrList.stream().allMatch(vtr -> vtr.getCredentialTrustLevel().equals(MEDIUM_LEVEL));
    }
}
