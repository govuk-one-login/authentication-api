package uk.gov.di.orchestration.shared.services;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.AuthUserInfo;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class AuthenticationUserInfoStorageService extends BaseDynamoService<AuthUserInfo> {

    private static final Logger LOG =
            LogManager.getLogger(AuthenticationUserInfoStorageService.class);
    private final long timeToExist;

    public AuthenticationUserInfoStorageService(ConfigurationService configurationService) {
        super(AuthUserInfo.class, "Auth-User-Info", configurationService, true);
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
        put(userInfoDbObject);
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
        Optional<AuthUserInfo> authUserInfo = get(subjectID, clientSessionId);
        if (authUserInfo.isEmpty()) {
            LOG.info(
                    "no auth user for subject Id {} and client Session id {}",
                    subjectID,
                    clientSessionId);
        }
        return authUserInfo.filter(
                t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }
}
