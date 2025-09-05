package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.exceptions.JwksCacheException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class JwksCacheService extends BaseDynamoService<JwksCacheItem> {
    private static final Logger LOG = LogManager.getLogger(JwksCacheService.class);

    private final long timeToLive;
    private final NowHelper.NowClock nowClock;

    public JwksCacheService(ConfigurationService configurationService, Clock clock) {
        super(JwksCacheItem.class, "Jwks-Cache", configurationService, true);
        this.timeToLive = configurationService.getJwkCacheExpirationInSeconds();
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
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public JwksCacheService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<JwksCacheItem> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public void storeKey(JwksCacheItem jwksCacheItem) {
        var item =
                jwksCacheItem.withTimeToLive(
                        nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            LOG.error("Failed to add JWKS cache item. Error message: {}", e.getMessage());
            throw new JwksCacheException("Failed to add JWKS cache item.");
        }
    }

    public Optional<JwksCacheItem> getEncryptionKey(String jwksUrl) {
        Optional<JwksCacheItem> jwksCacheItem =
                queryTableStream(jwksUrl)
                        .filter(item -> KeyUse.ENCRYPTION.getValue().equals(item.getKeyUse()))
                        .findFirst();

        if (jwksCacheItem.isEmpty()) {
            return jwksCacheItem;
        }

        Optional<JwksCacheItem> validJwksCacheItem =
                jwksCacheItem.filter(
                        s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());

        return validJwksCacheItem;
    }
}
