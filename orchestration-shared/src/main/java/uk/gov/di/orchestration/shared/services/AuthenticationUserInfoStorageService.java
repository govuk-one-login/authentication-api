package uk.gov.di.orchestration.shared.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.AuthUserInfo;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class AuthenticationUserInfoStorageService {

    private final long timeToExist;
    private final BaseDynamoService<AuthUserInfo> authUserInfoDynamoService;

    public AuthenticationUserInfoStorageService(ConfigurationService configurationService) {
        authUserInfoDynamoService =
                new BaseDynamoService<>(
                        AuthUserInfo.class, "Auth-User-Info", configurationService, true);
        this.timeToExist = 21600L; // 6 hours
    }

    public void addAuthenticationUserInfoData(
            String subjectID, String clientSessionId, UserInfo userInfo) {
        String userInfoJson = userInfo.toJSONString();
        var userInfoDbObject =
                new AuthUserInfo()
                        .withInternalCommonSubjectId(subjectID)
                        .withClientSessionId(clientSessionId)
                        .withUserInfo(userInfoJson)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        authUserInfoDynamoService.put(userInfoDbObject);
    }

    public Optional<UserInfo> getAuthenticationUserInfo(String subjectID, String clientSessionId)
            throws com.nimbusds.oauth2.sdk.ParseException {
        var userInfoData = getAuthUserInfoData(subjectID, clientSessionId);
        if (userInfoData.isEmpty()) {
            return Optional.empty();
        }
        var userInfo = UserInfo.parse(userInfoData.get().getUserInfo());
        return Optional.of(userInfo);
    }

    private Optional<AuthUserInfo> getAuthUserInfoData(String subjectID, String clientSessionId) {
        return authUserInfoDynamoService
                .get(subjectID, clientSessionId)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }
}
