package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.RpPublicKeyCache;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class RpPublicKeyCacheService extends BaseDynamoService<RpPublicKeyCache> {

    private static final Logger LOG = LogManager.getLogger(RpPublicKeyCacheService.class);

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
        Optional<RpPublicKeyCache> cacheData = get(clientId, keyId);

        if (cacheData.isEmpty()) {
            LOG.info("No cached RP public key found with key ID {}", keyId);
            return cacheData;
        }

        Optional<RpPublicKeyCache> validCacheData =
                cacheData.filter(
                        data ->
                                data.getTimeToLive()
                                        > NowHelper.now().toInstant().getEpochSecond());

        if (validCacheData.isEmpty()) {
            LOG.info("Cached RP public key with expired TTL found. Key ID: {}", keyId);
        }
        return validCacheData;
    }
}
