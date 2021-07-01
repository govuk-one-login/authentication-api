package uk.gov.di.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface AuthenticationService {
    boolean userExists(String email);

    void signUp(String email, String password);

    boolean login(String email, String password);

    boolean isEmailVerificationRequired();

    UserInfo getInfoForEmail(String email);
}
