package uk.gov.di.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface AuthenticationService {
    public boolean userExists(String email);

    public void signUp(String email, String password);

    public boolean verifyAccessCode(String username, String code);

    public boolean login(String email, String password);

    public boolean isEmailVerificationRequired();

    public UserInfo getInfoForEmail(String email);
}
