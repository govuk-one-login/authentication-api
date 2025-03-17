package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.User;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;

import java.time.LocalDateTime;
import java.util.Optional;

public interface AuthenticationService {
    boolean userExists(String email);

    User signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions);

    boolean login(String email, String password);

    boolean login(UserCredentials credentials, String password);

    Subject getSubjectFromEmail(String email);

    void updatePhoneNumber(String email, String profileInformation);

    /**
     * Deprecated - use getUserProfileByEmailMaybe instead. Can't literally deprecate it, because
     * -Werror will complain.
     */
    UserProfile getUserProfileByEmail(String email);

    Optional<UserProfile> getUserProfileByEmailMaybe(String email);

    void updatePhoneNumberAndAccountVerifiedStatus(
            String email, String phoneNumber, boolean phoneNumberVerified, boolean accountVerified);

    void setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(String email, String phoneNumber);

    void setAccountVerified(String email);

    Optional<String> getPhoneNumber(String email);

    UserProfile getUserProfileFromSubject(String subject);

    Optional<UserProfile> getOptionalUserProfileFromPublicSubject(String subject);

    void updateTermsAndConditions(String email, String version);

    void updateEmail(String currentEmail, String newEmail);

    void updateEmail(String currentEmail, String newEmail, LocalDateTime updatedDateTime);

    void updatePassword(String email, String newPassword);

    void removeAccount(String email);

    UserCredentials getUserCredentialsFromSubject(String subject);

    Optional<UserProfile> getUserProfileFromEmail(String email);

    UserCredentials getUserCredentialsFromEmail(String email);

    void migrateLegacyPassword(String email, String password);

    byte[] getOrGenerateSalt(UserProfile userProfile);

    void updateMFAMethod(
            String email,
            MFAMethodType mfaMethodType,
            boolean methodVerified,
            boolean enabled,
            String credentialValue);

    void addMFAMethodSupportingMultiple(String email, MFAMethod mfaData);

    void setAuthAppAndAccountVerified(String email, String credentialValue);

    void setVerifiedAuthAppAndRemoveExistingMfaMethod(String email, String credentialValue);

    void setMfaMethodsMigrated(String email, boolean mfaMethodsMigrated);

    void deleteMfaMethodByIdentifier(String email, String mfaMethodIdentifier);
}
