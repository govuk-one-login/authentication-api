package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.AuthenticationUserInfo;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class AuthenticationUserInfoStorageService
        extends BaseDynamoService<AuthenticationUserInfo> {

    private final long timeToExist;

    public AuthenticationUserInfoStorageService(ConfigurationService configurationService) {
        super(
                AuthenticationUserInfo.class,
                "authentication-callback-userinfo",
                configurationService);
        this.timeToExist = 21600L; // 6 hours
    }

    public void addAuthenticationUserInfoData(String subjectID, UserInfo userInfo) {
        String userInfoJson = userInfo.toJSONString();
        var userInfoDbObject =
                new AuthenticationUserInfo()
                        .withSubjectID(subjectID)
                        .withUserInfo(userInfoJson)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        put(userInfoDbObject);
    }

    public Optional<UserInfo> getAuthenticationUserInfo(OrchSessionItem orchSession)
            throws ParseException {
        var authenticationUserInfo = getAuthenticationUserInfoData(orchSession.getEmailAddress());
        var userInfo =
                new UserInfo(JSONObjectUtils.parse(authenticationUserInfo.get().getUserInfo()));
        return Optional.ofNullable(userInfo);
    }

    public Optional<AuthenticationUserInfo> getAuthenticationUserInfoData(String subjectID) {
        return get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }
}
