package uk.gov.di.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface UserInfoService {

    UserInfo getInfoForEmail(String email);
}
