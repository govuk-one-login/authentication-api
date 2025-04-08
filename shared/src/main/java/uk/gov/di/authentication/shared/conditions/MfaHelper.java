package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class MfaHelper {
    private static final Logger LOG = LogManager.getLogger(MfaHelper.class);

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

        return mfaRequired(vectorOfTrust.getCredentialTrustLevel());
    }

    public static boolean mfaRequired(CredentialTrustLevel credentialTrustLevel) {
        return !Objects.equals(credentialTrustLevel, LOW_LEVEL);
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
        var isMfaRequired = mfaRequired(userContext.getClientSession().getAuthRequestParams());
        return getUserMFADetail(isMfaRequired, userCredentials, phoneNumber, isPhoneNumberVerified);
    }

    public static UserMfaDetail getUserMFADetail(
            CredentialTrustLevel credentialTrustLevel,
            UserCredentials userCredentials,
            String phoneNumber,
            boolean isPhoneNumberVerified) {
        var isMfaRequired = mfaRequired(credentialTrustLevel);
        return getUserMFADetail(isMfaRequired, userCredentials, phoneNumber, isPhoneNumberVerified);
    }

    private static UserMfaDetail getUserMFADetail(
            boolean isMfaRequired,
            UserCredentials userCredentials,
            String phoneNumber,
            boolean isPhoneNumberVerified) {
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
