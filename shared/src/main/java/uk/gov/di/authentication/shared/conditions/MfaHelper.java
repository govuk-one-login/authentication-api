package uk.gov.di.authentication.shared.conditions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

public class MfaHelper {
    private static final Logger LOG = LogManager.getLogger(MfaHelper.class);

    private MfaHelper() {}

    public static boolean mfaRequired(CredentialTrustLevel credentialTrustLevel) {
        return !Objects.equals(credentialTrustLevel, LOW_LEVEL);
    }

    public static Optional<MFAMethod> getPrimaryMFAMethod(UserCredentials userCredentials) {
        return Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mfaMethods -> mfaMethods.stream().filter(MFAMethod::isEnabled).findFirst());
    }

    public static Optional<MFAMethod> getDefaultMfaMethodForMigratedUser(
            UserCredentials userCredentials) {
        return userCredentials.getMfaMethods().stream()
                .filter(mfaMethod -> DEFAULT.name().equals(mfaMethod.getPriority()))
                .findFirst();
    }

    public static UserMfaDetail getUserMFADetail(
            CredentialTrustLevel credentialTrustLevel,
            UserCredentials userCredentials,
            UserProfile userProfile) {
        var isMfaRequired = mfaRequired(credentialTrustLevel);
        if (userProfile.isMfaMethodsMigrated()) {
            return getMfaDetailForMigratedUser(userCredentials, isMfaRequired);
        } else {
            return getMfaDetailForNonMigratedUser(
                    userCredentials,
                    userProfile.getPhoneNumber(),
                    userProfile.isPhoneNumberVerified(),
                    isMfaRequired);
        }
    }

    private static UserMfaDetail getMfaDetailForNonMigratedUser(
            UserCredentials userCredentials,
            String phoneNumber,
            boolean isPhoneVerified,
            boolean isMfaRequired) {
        var enabledMethod = getPrimaryMFAMethod(userCredentials);

        if (enabledMethod.filter(MFAMethod::isMethodVerified).isPresent()) {
            LOG.info("User has verified method from user credentials");
            var mfaMethodType = MFAMethodType.valueOf(enabledMethod.get().getMfaMethodType());
            return new UserMfaDetail(isMfaRequired, true, mfaMethodType, phoneNumber);
        } else if (!isPhoneVerified && enabledMethod.isPresent()) {
            LOG.info("Unverified auth app mfa method present and no verified phone number");
            var mfaMethodType = MFAMethodType.valueOf(enabledMethod.get().getMfaMethodType());
            return new UserMfaDetail(isMfaRequired, false, mfaMethodType, phoneNumber);
        } else {
            var mfaMethodType = isPhoneVerified ? MFAMethodType.SMS : MFAMethodType.NONE;
            LOG.info("User has mfa method {}", mfaMethodType);
            return new UserMfaDetail(isMfaRequired, isPhoneVerified, mfaMethodType, phoneNumber);
        }
    }

    private static UserMfaDetail getMfaDetailForMigratedUser(
            UserCredentials userCredentials, boolean isMfaRequired) {
        var maybeDefaultMethod = MfaHelper.getDefaultMfaMethodForMigratedUser(userCredentials);
        if (maybeDefaultMethod.isPresent()) {
            var defaultMethod = maybeDefaultMethod.get();
            String phoneNumberForMigratedMethod;
            if (defaultMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
                phoneNumberForMigratedMethod = defaultMethod.getDestination();
            } else {
                phoneNumberForMigratedMethod = null;
            }
            return new UserMfaDetail(
                    isMfaRequired,
                    defaultMethod.isMethodVerified(),
                    MFAMethodType.valueOf(defaultMethod.getMfaMethodType()),
                    phoneNumberForMigratedMethod);
        } else {
            var mfaMethodCount = userCredentials.getMfaMethods().size();
            var mfaMethodPrioritiesForUser =
                    userCredentials.getMfaMethods().stream()
                            .map(MFAMethod::getPriority)
                            .collect(Collectors.joining(", "));

            LOG.error(
                    "Unexpected error retrieving default mfa method for migrated user: no default method exists. User MFA method count: {}, MFA method priorities: {}",
                    mfaMethodCount,
                    mfaMethodPrioritiesForUser);
            return new UserMfaDetail(isMfaRequired, false, MFAMethodType.NONE, null);
        }
    }
}
