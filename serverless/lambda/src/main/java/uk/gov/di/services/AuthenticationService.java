package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.id.Subject;

import java.util.Optional;

public interface AuthenticationService {
    boolean userExists(String email);

    void signUp(String email, String password);

    boolean login(String email, String password);

    boolean isEmailVerificationRequired();

    Subject getSubjectFromEmail(String email);

    void updatePhoneNumber(String email, String profileInformation);

    void updatePhoneNumberVerifiedStatus(String email, boolean verifiedStatus);

    Optional<String> getPhoneNumber(String email);
}
