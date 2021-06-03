package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.util.HashMap;
import java.util.Map;

public class InMemoryUserInfoService implements UserInfoService {

    private static final Map<String, UserInfo> USER_INFO = new HashMap<>() {{
        put("joe.bloggs@digital.cabinet-office.gov.uk", new UserInfo(new Subject()) {{
            setGivenName("Joe");
            setFamilyName("Bloggs");
            setEmailAddress("joe.bloggs@digital.cabinet-office.gov.uk");
        }});
    }};

    @Override
    public UserInfo getInfoForEmail(String email) {
        return USER_INFO.get(email);
    }
}
