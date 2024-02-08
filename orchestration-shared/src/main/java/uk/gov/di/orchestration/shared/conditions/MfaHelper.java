package uk.gov.di.orchestration.shared.conditions;

import uk.gov.di.orchestration.shared.entity.MFAMethod;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

public class MfaHelper {

    private MfaHelper() {}

    public static boolean mfaRequired(List<VectorOfTrust> vtrList) {
        return vtrList.stream().allMatch(vtr -> vtr.getCredentialTrustLevel().equals(MEDIUM_LEVEL));
    }

    public static Optional<MFAMethod> getPrimaryMFAMethod(UserCredentials userCredentials) {
        return Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mfaMethods -> mfaMethods.stream().filter(MFAMethod::isEnabled).findFirst());
    }
}
