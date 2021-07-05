package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.id.Subject;

public interface AuthenticationService {
    boolean userExists(String email);

    void signUp(String email, String password);

    boolean login(String email, String password);

    boolean isEmailVerificationRequired();

    Subject getSubjectFromEmail(String email);

    void updatePhoneNumber(String email, String profileInformation);
}
