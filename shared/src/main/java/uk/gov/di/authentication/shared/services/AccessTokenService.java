package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class AccessTokenService extends BaseDynamoService<AccessTokenStore> {

    private final long timeToExist;
    private final boolean isAccessTokenStoreEnabled;

    public AccessTokenService(
            ConfigurationService configurationService, boolean isAccessTokenStoreEnabled) {
        super(AccessTokenStore.class, "access-token-store", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.isAccessTokenStoreEnabled = isAccessTokenStoreEnabled;
    }

    public AccessTokenService(ConfigurationService configurationService) {
        super(AccessTokenStore.class, "access-token-store", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.isAccessTokenStoreEnabled = configurationService.isAccessTokenStoreEnabled();
    }

    public void addAccessTokenStore(String accessToken, String subjectID, List<String> scopes) {
        if (isAccessTokenStoreEnabled) {
            var tokenStore =
                    get(accessToken)
                            .orElse(new AccessTokenStore())
                            .withAccessToken(accessToken)
                            .withSubjectID(subjectID)
                            .withScopes(scopes)
                            .withUsed(false)
                            .withTimeToExist(
                                    NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                            .toInstant()
                                            .getEpochSecond());
            update(tokenStore);
        }
    }

    public Optional<AccessTokenStore> getAccessTokenStore(String accessToken) {
        return isAccessTokenStoreEnabled
                ? get(accessToken)
                        .filter(
                                t ->
                                        t.getTimeToExist()
                                                > NowHelper.now().toInstant().getEpochSecond())
                : Optional.empty();
    }

    public Optional<AccessTokenStore> setAccessTokenStoreUsed(String accessToken, boolean used) {
        return isAccessTokenStoreEnabled
                ? get(accessToken)
                        .map(
                                ts -> {
                                    ts.setUsed(used);
                                    update(ts);
                                    return ts;
                                })
                : Optional.empty();
    }
}
