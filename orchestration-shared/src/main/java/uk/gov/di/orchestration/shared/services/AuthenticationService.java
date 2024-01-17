package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.shared.entity.ClientConsent;
import uk.gov.di.orchestration.shared.entity.TermsAndConditions;
import uk.gov.di.orchestration.shared.entity.User;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;

import java.util.Optional;

public interface AuthenticationService {

    User signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions);

    boolean login(String email, String password);

    boolean login(UserCredentials credentials, String password);

    void updateConsent(String email, ClientConsent clientConsent);

    /**
     * Deprecated - use getUserProfileByEmailMaybe instead. Can't literally deprecate it, because
     * -Werror will complain.
     */
    UserProfile getUserProfileByEmail(String email);

    Optional<UserProfile> getUserProfileByEmailMaybe(String email);

    void updatePhoneNumberAndAccountVerifiedStatus(
            String email, String phoneNumber, boolean phoneNumberVerified, boolean accountVerified);

    Optional<String> getPhoneNumber(String email);

    UserProfile getUserProfileFromSubject(String subject);

    Optional<UserProfile> getUserProfileFromEmail(String email);

    UserCredentials getUserCredentialsFromEmail(String email);

    byte[] getOrGenerateSalt(UserProfile userProfile);
}
