package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.shared.entity.ClientConsent;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.TermsAndConditions;
import uk.gov.di.orchestration.shared.entity.User;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface AuthenticationService {
    boolean userExists(String email);

    User signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions);

    boolean login(String email, String password);

    boolean login(UserCredentials credentials, String password);

    Subject getSubjectFromEmail(String email);

    void updatePhoneNumber(String email, String profileInformation);

    void updateConsent(String email, ClientConsent clientConsent);

    /**
     * Deprecated - use getUserProfileByEmailMaybe instead. Can't literally deprecate it, because
     * -Werror will complain.
     */
    UserProfile getUserProfileByEmail(String email);

    Optional<UserProfile> getUserProfileByEmailMaybe(String email);

    Optional<List<ClientConsent>> getUserConsents(String email);

    void updatePhoneNumberAndAccountVerifiedStatus(
            String email, String phoneNumber, boolean phoneNumberVerified, boolean accountVerified);

    void setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(String email, String phoneNumber);

    void setAccountVerified(String email);

    Optional<String> getPhoneNumber(String email);

    UserProfile getUserProfileFromSubject(String subject);

    UserProfile getUserProfileFromPublicSubject(String subject);

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

    void setAuthAppAndAccountVerified(String email, String credentialValue);

    void setVerifiedAuthAppAndRemoveExistingMfaMethod(String email, String credentialValue);
}
