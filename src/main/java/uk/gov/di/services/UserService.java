package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.Gender;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class UserService implements AuthenticationService {

    private static final Logger LOG = LoggerFactory.getLogger(UserService.class);

    private final Map<String, String> credentialsMap =
            new HashMap<>(Map.of("joe.bloggs@digital.cabinet-office.gov.uk", "password"));
    private final Map<String, UserInfo> userInfoMap = new HashMap<>();

    public UserService() {
        UserInfo userInfo = new UserInfo(new Subject());
        userInfo.setFamilyName("Bloggs");
        userInfo.setGivenName("Joe");
        userInfo.setEmailAddress("joe.bloggs@digital.cabinet-office.gov.uk");
        userInfo.setGender(Gender.MALE);

        userInfoMap.put("joe.bloggs@digital.cabinet-office.gov.uk", userInfo);
    }

    @Override
    public boolean isEmailVerificationRequired() {
        return false;
    }

    @Override
    public boolean signUp(String email, String password) {
        LOG.info("UserService.signup: {}", email);
        credentialsMap.put(email, password);
        UserInfo userInfo = new UserInfo(new Subject());
        userInfo.setEmailAddress(email);
        userInfoMap.put(email, userInfo);
        return true;
    }

    @Override
    public boolean verifyAccessCode(String username, String code) {
        return true;
    }

    @Override
    public boolean login(String email, String password) {
        return credentialsMap.containsKey(email) && credentialsMap.get(email).equals(password);
    }

    @Override
    public boolean userExists(String email) {
        return credentialsMap.containsKey(email);
    }

    @Override
    public UserInfo getInfoForEmail(String email) {
        return userInfoMap.get(email);
    }
}
