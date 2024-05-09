package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.ClientConsent;
import uk.gov.di.orchestration.shared.entity.UserProfile;

import java.util.Optional;

public interface AuthenticationService {

    void updateConsent(String email, ClientConsent clientConsent);

    /**
     * Deprecated - use getUserProfileByEmailMaybe instead. Can't literally deprecate it, because
     * -Werror will complain.
     */
    UserProfile getUserProfileByEmail(String email);

    Optional<UserProfile> getUserProfileByEmailMaybe(String email);

    void updatePhoneNumberAndAccountVerifiedStatus(
            String email, String phoneNumber, boolean phoneNumberVerified, boolean accountVerified);

    UserProfile getUserProfileFromSubject(String subject);

    Optional<UserProfile> getUserProfileFromEmail(String email);

    byte[] getOrGenerateSalt(UserProfile userProfile);
}
