package uk.gov.di.authentication.shared.conditions;

import uk.gov.di.authentication.shared.entity.LevelOfConfidence;

import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            LevelOfConfidence levelOfConfidence,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        if (!clientSupportsIdentityVerification || !identityEnabled) {
            return false;
        }

        return Objects.nonNull(levelOfConfidence) && !(levelOfConfidence.equals(NONE));
    }
}
