package uk.gov.di.authentication.shared.conditions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class MfaHelper {
    private static final Logger LOG = LogManager.getLogger(MfaHelper.class);

    private MfaHelper() {}

    public static boolean mfaRequired(Optional<VectorOfTrust> effectiveVectorOfTrust) {
        return effectiveVectorOfTrust
                .map(vtr -> !vtr.getCredentialTrustLevel().equals(LOW_LEVEL))
                .orElse(false);
    }

    public static Optional<MFAMethod> getPrimaryMFAMethod(UserCredentials userCredentials) {
        return Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mfaMethods -> mfaMethods.stream().filter(MFAMethod::isEnabled).findFirst());
    }

    public static UserMfaDetail getUserMFADetail(
            UserContext userContext,
            UserCredentials userCredentials,
            String phoneNumber,
            boolean isPhoneNumberVerified) {
        var isMfaRequired = mfaRequired(userContext.getAuthSession().getEffectiveVectorOfTrust());

        var enabledMethod = getPrimaryMFAMethod(userCredentials);

        if (enabledMethod.filter(MFAMethod::isMethodVerified).isPresent()) {
            LOG.info("User has verified method from user credentials");
            var mfaMethodType = MFAMethodType.valueOf(enabledMethod.get().getMfaMethodType());
            return new UserMfaDetail(isMfaRequired, true, mfaMethodType, phoneNumber);
        } else if (!isPhoneNumberVerified && enabledMethod.isPresent()) {
            LOG.info("Unverified auth app mfa method present and no verified phone number");
            var mfaMethodType = MFAMethodType.valueOf(enabledMethod.get().getMfaMethodType());
            return new UserMfaDetail(isMfaRequired, false, mfaMethodType, phoneNumber);
        } else {
            var mfaMethodType = isPhoneNumberVerified ? MFAMethodType.SMS : MFAMethodType.NONE;
            LOG.info("User has mfa method {}", mfaMethodType);
            return new UserMfaDetail(
                    isMfaRequired, isPhoneNumberVerified, mfaMethodType, phoneNumber);
        }
    }
}
