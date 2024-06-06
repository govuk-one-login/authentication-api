package uk.gov.di.orchestration.shared.conditions;

import uk.gov.di.orchestration.shared.entity.VtrList;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            VtrList vtrList, boolean clientSupportsIdentityVerification, boolean identityEnabled) {
        if (!clientSupportsIdentityVerification || !identityEnabled) {
            return false;
        }
        return vtrList.identityRequired();
    }
}
