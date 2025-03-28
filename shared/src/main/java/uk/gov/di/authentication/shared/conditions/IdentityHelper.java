package uk.gov.di.authentication.shared.conditions;

import uk.gov.di.authentication.shared.entity.VectorOfTrust;

import java.util.List;
import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            List<VectorOfTrust> vtrList,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        if (!clientSupportsIdentityVerification
                || !identityEnabled
                || Objects.isNull(vtrList)
                || vtrList.isEmpty()) {
            return false;
        }
        var vectorOfTrust = vtrList.get(0);
        return Objects.nonNull(vectorOfTrust.getLevelOfConfidence())
                && !(vectorOfTrust.getLevelOfConfidence().equals(NONE));
    }
}
