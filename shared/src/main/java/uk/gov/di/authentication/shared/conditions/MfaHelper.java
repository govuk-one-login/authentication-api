package uk.gov.di.authentication.shared.conditions;

import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class MfaHelper {

    private MfaHelper() {}

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
        var isMfaRequired = userContext.getClientSession().getMfaRequired();
        var mfaMethodVerified = isPhoneNumberVerified;
        var mfaMethodType = isPhoneNumberVerified ? MFAMethodType.SMS : MFAMethodType.NONE;

        var mfaMethod = getPrimaryMFAMethod(userCredentials);
        if (mfaMethod.filter(MFAMethod::isMethodVerified).isPresent()) {
            mfaMethodVerified = true;
            mfaMethodType = MFAMethodType.valueOf(mfaMethod.get().getMfaMethodType());
        } else if (!isPhoneNumberVerified && mfaMethod.isPresent()) {
            mfaMethodType = MFAMethodType.valueOf(mfaMethod.get().getMfaMethodType());
        }
        return new UserMfaDetail(isMfaRequired, mfaMethodVerified, mfaMethodType, phoneNumber);
    }
}
