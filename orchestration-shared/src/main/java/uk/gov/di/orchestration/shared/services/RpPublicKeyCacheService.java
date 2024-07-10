package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.RpPublicKeyCache;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class RpPublicKeyCacheService extends BaseDynamoService<RpPublicKeyCache> {

    private final long timeToLive;

    public RpPublicKeyCacheService(ConfigurationService configurationService) {
        super(RpPublicKeyCache.class, "RpPublicKeyCache", configurationService, true);
        this.timeToLive = 86400L; // 24 hours
    }

    public void addRpPublicKeyCacheData(String clientId, String keyId, String publicKey) {
        var dbObject =
                new RpPublicKeyCache()
                        .withClientId(clientId)
                        .withKeyId(keyId)
                        .withPublicKey(publicKey)
                        .withTimeToLive(
                                NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        put(dbObject);
    }

    public Optional<RpPublicKeyCache> getRpPublicKeyCacheData(String clientId, String keyId) {
        return get(clientId, keyId)
                .filter(t -> t.getTimeToLive() > NowHelper.now().toInstant().getEpochSecond());
    }
}
