package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.Objects;

public class UserInfoService {

    private final AuthenticationService authenticationService;
    private final DynamoSpotService spotService;

    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            AuthenticationService authenticationService, DynamoSpotService spotService) {
        this.authenticationService = authenticationService;
        this.spotService = spotService;
    }

    public UserInfo populateUserInfo(AccessTokenInfo accessTokenInfo, boolean identityEnabled) {
        LOG.info("Populating UserInfo");
        var userProfile =
                authenticationService.getUserProfileFromSubject(
                        accessTokenInfo.getAccessTokenStore().getInternalSubjectId());
        var userInfo = new UserInfo(new Subject(accessTokenInfo.getPublicSubject()));
        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.EMAIL.getValue())) {
            userInfo.setEmailAddress(userProfile.getEmail());
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.PHONE.getValue())) {
            userInfo.setPhoneNumber(userProfile.getPhoneNumber());
            userInfo.setPhoneNumberVerified(userProfile.isPhoneNumberVerified());
        }
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.GOVUK_ACCOUNT.getValue())) {
            userInfo.setClaim("legacy_subject_id", userProfile.getLegacySubjectID());
        }
        if (identityEnabled) {
            return populateIdentityInfo(accessTokenInfo, userInfo);
        } else {
            return userInfo;
        }
    }

    private UserInfo populateIdentityInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating IdentityInfo");
        var spotCredential = spotService.getSpotCredential(accessTokenInfo.getPublicSubject());
        if (spotCredential.isEmpty() || Objects.isNull(accessTokenInfo.getIdentityClaims())) {
            return userInfo;
        }
        var address =
                accessTokenInfo.getIdentityClaims().stream()
                        .filter(t -> t.equals(ValidClaims.ADDRESS))
                        .findFirst()
                        .orElse(null);
        if (Objects.nonNull(address) && Objects.nonNull(spotCredential.get().getAddress())) {
            userInfo.setClaim("address", spotCredential.get().getAddress());
        }
        var passportNumber =
                accessTokenInfo.getIdentityClaims().stream()
                        .filter(t -> t.equals(ValidClaims.PASSPORT_NUMBER))
                        .findFirst()
                        .orElse(null);
        if (Objects.nonNull(passportNumber)
                && Objects.nonNull(spotCredential.get().getPassportNumber())) {
            userInfo.setClaim("passport-number", spotCredential.get().getPassportNumber());
        }
        if (Objects.nonNull(spotCredential.get().getSerializedCredential())) {
            userInfo.setClaim("identity", spotCredential.get().getSerializedCredential());
        }
        return userInfo;
    }
}
