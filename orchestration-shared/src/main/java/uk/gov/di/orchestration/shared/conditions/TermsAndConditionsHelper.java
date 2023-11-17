package uk.gov.di.orchestration.shared.conditions;

import uk.gov.di.orchestration.shared.entity.TermsAndConditions;

public class TermsAndConditionsHelper {

    private TermsAndConditionsHelper() {}

    public static boolean hasTermsAndConditionsBeenAccepted(
            TermsAndConditions termsAndConditions, String latestVersion, boolean smokeTestClient) {
        if (smokeTestClient) return true;
        if (latestVersion == null) return false;
        return termsAndConditions.getVersion().equals(latestVersion);
    }
}
