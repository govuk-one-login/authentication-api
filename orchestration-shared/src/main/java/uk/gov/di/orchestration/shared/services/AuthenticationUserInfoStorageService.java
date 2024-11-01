package uk.gov.di.orchestration.shared.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.AuthenticationUserInfo;
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

    public Optional<UserInfo> getAuthenticationUserInfo(String subjectID)
            throws com.nimbusds.oauth2.sdk.ParseException {
        var userInfoData = getAuthenticationUserInfoData(subjectID);
        if (userInfoData.isEmpty()) {
            return Optional.empty();
        }
        var userInfo = UserInfo.parse(userInfoData.get().getUserInfo());
        return Optional.ofNullable(userInfo);
    }

    public Optional<AuthenticationUserInfo> getAuthenticationUserInfoData(String subjectID) {
        return get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }
}
