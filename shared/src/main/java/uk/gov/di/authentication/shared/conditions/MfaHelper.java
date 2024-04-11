package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class MfaHelper {

    private MfaHelper() {}

    public static boolean mfaRequired(Map<String, List<String>> authRequestParams) {
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(authRequestParams);
        } catch (ParseException e) {
            throw new RuntimeException();
        }
        List<String> vtr = authRequest.getCustomParameter("vtr");
        VectorOfTrust vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(vtr);

        return !vectorOfTrust.getCredentialTrustLevel().equals(LOW_LEVEL);
    }

    public static UserMfaDetail getUserMFADetail(
            UserContext userContext,
            UserCredentials userCredentials,
            String phoneNumber,
            boolean isPhoneNumberVerified) {
        var clientSession = userContext.getClientSession();
        var mfaRequired = clientSession.getMfaRequired();
        // ATO-98: This should only ever be null if a session was in progress during release.
        boolean isMfaRequired = mfaRequired != null
                ? mfaRequired
                : mfaRequired(userContext.getClientSession().getAuthRequestParams());
        var mfaMethodVerified = isPhoneNumberVerified;

        var mfaMethod = getPrimaryMFAMethod(userCredentials);
        var mfaMethodType = MFAMethodType.SMS;
        if (mfaMethod.filter(MFAMethod::isMethodVerified).isPresent()) {
            mfaMethodVerified = true;
            mfaMethodType = MFAMethodType.valueOf(mfaMethod.get().getMfaMethodType());
        } else if (!isPhoneNumberVerified && mfaMethod.isPresent()) {
            mfaMethodType = MFAMethodType.valueOf(mfaMethod.get().getMfaMethodType());
        }
        return new UserMfaDetail(isMfaRequired, mfaMethodVerified, mfaMethodType, phoneNumber);
    }

    private static Optional<MFAMethod> getPrimaryMFAMethod(UserCredentials userCredentials) {
        return Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mfaMethods -> mfaMethods.stream().filter(MFAMethod::isEnabled).findFirst());
    }
}
