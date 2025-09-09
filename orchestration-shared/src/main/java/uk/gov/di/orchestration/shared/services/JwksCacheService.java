package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.exceptions.JwksCacheException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class JwksCacheService extends BaseDynamoService<JwksCacheItem> {
    private static final Logger LOG = LogManager.getLogger(JwksCacheService.class);

    private final long timeToLive;
    private final ConfigurationService configurationService;
    private final NowHelper.NowClock nowClock;

    public JwksCacheService(ConfigurationService configurationService, Clock clock) {
        super(JwksCacheItem.class, "Jwks-Cache", configurationService, true);
        this.timeToLive = configurationService.getJwkCacheExpirationInSeconds();
        this.configurationService = configurationService;
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public JwksCacheService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public JwksCacheService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<JwksCacheItem> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.timeToLive = configurationService.getJwkCacheExpirationInSeconds();
        this.configurationService = configurationService;
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public JwksCacheService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<JwksCacheItem> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public JwksCacheItem getOrGenerateIpvJwksCacheItem() {
        URL ipvUrl = configurationService.getIPVJwksUrl();
        return getOrGenerateJwksCacheItem(ipvUrl);
    }

    public JwksCacheItem getOrGenerateDocAppJwksCacheItem() {
        URL docAppsUrl = configurationService.getDocAppJwksUrl();
        return getOrGenerateJwksCacheItem(docAppsUrl);
    }

    private JwksCacheItem getOrGenerateJwksCacheItem(URL url) {
        Optional<JwksCacheItem> jwkCacheItem = getEncryptionKey(url.toString());
        if (jwkCacheItem.isEmpty()) {
            LOG.info(
                    "Cache entry does not exist for JWKS URL {}, creating new one with expiration of {} seconds",
                    url.toString(),
                    timeToLive);
            JwksCacheItem newJwksCacheItem = createJwks(url);
            storeKey(newJwksCacheItem);
            return newJwksCacheItem;
        }

        return jwkCacheItem.get();
    }

    private JwksCacheItem createJwks(URL jwksUrl) {
        long ttl = nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS).toInstant().getEpochSecond();
        JWK key = JwksUtils.getKey(jwksUrl, KeyUse.ENCRYPTION);
        return new JwksCacheItem(jwksUrl.toString(), key, ttl);
    }

    private void storeKey(JwksCacheItem jwksCacheItem) {
        try {
            put(jwksCacheItem);
        } catch (Exception e) {
            LOG.error("Failed to add JWKS cache item. Error message: {}", e.getMessage());
            throw new JwksCacheException("Failed to add JWKS cache item.");
        }
    }

    private Optional<JwksCacheItem> getEncryptionKey(String jwksUrl) {
        Optional<JwksCacheItem> jwksCacheItem =
                queryTableStream(jwksUrl)
                        .filter(item -> KeyUse.ENCRYPTION.getValue().equals(item.getKeyUse()))
                        .findFirst();

        return jwksCacheItem.filter(
                s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
    }
}
