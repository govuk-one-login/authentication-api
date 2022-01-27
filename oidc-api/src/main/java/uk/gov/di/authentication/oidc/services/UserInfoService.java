package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

public class UserInfoService {

    private final AuthenticationService authenticationService;

    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public UserInfo populateUserInfo(AccessTokenInfo accessTokenInfo) {
        LOG.info("Populating UserInfo");
        UserProfile userProfile =
                authenticationService.getUserProfileFromSubject(
                        accessTokenInfo.getAccessTokenStore().getInternalSubjectId());
        UserInfo userInfo = new UserInfo(new Subject(accessTokenInfo.getPublicSubject()));
        if (accessTokenInfo.getScopes().contains("email")) {
            userInfo.setEmailAddress(userProfile.getEmail());
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (accessTokenInfo.getScopes().contains("phone")) {
            userInfo.setPhoneNumber(userProfile.getPhoneNumber());
            userInfo.setPhoneNumberVerified(userProfile.isPhoneNumberVerified());
        }
        if (accessTokenInfo.getScopes().contains("govuk-account")) {
            userInfo.setClaim("legacy_subject_id", userProfile.getLegacySubjectID());
        }
        return userInfo;
    }
}
