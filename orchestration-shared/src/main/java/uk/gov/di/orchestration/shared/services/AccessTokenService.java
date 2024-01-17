package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.token.AccessTokenStore;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class AccessTokenService extends BaseDynamoService<AccessTokenStore> {
    private static final Logger LOG = LogManager.getLogger(AccessTokenService.class);
    private final long timeToExist;
    private final boolean isAccessTokenStoreEnabled;

    public AccessTokenService(
            ConfigurationService configurationService, boolean isAccessTokenStoreEnabled) {
        super(AccessTokenStore.class, "access-token-store", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.isAccessTokenStoreEnabled = isAccessTokenStoreEnabled;
    }

    public AccessTokenService(ConfigurationService configurationService) {
        this(configurationService, configurationService.isAuthOrchSplitEnabled());
    }

    public void addAccessTokenStore(
            String accessToken,
            String subjectID,
            List<String> claims,
            boolean isNewAccount,
            String sectorIdentifier) {
        if (isAccessTokenStoreEnabled) {
            var tokenStore =
                    get(accessToken)
                            .orElse(new AccessTokenStore())
                            .withAccessToken(accessToken)
                            .withSubjectID(subjectID)
                            .withClaims(claims)
                            .withUsed(false)
                            .withNewAccount(isNewAccount)
                            .withSectorIdentifier(sectorIdentifier)
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

    public Optional<AccessTokenStore> setAccessTokenTtlTestOnly(String accessToken, long newTtl) {
        return isAccessTokenStoreEnabled
                ? get(accessToken)
                        .map(
                                ts -> {
                                    ts.setTimeToExist(newTtl);
                                    update(ts);
                                    return ts;
                                })
                : Optional.empty();
    }
}
