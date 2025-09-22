package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.CrossBrowserItem;
import uk.gov.di.orchestration.shared.exceptions.CrossBrowserStorageException;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;

public class CrossBrowserStorageService extends BaseDynamoService<CrossBrowserItem> {

    private static final Logger LOG = LogManager.getLogger(CrossBrowserStorageService.class);
    private final long expirationInSeconds;
    private final NowClock nowClock;

    public CrossBrowserStorageService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public CrossBrowserStorageService(ConfigurationService configurationService, Clock clock) {
        super(CrossBrowserItem.class, "Cross-Browser", configurationService, true);
        this.expirationInSeconds = configurationService.getSessionExpiry();
        this.nowClock = new NowClock(clock);
    }

    public CrossBrowserStorageService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<CrossBrowserItem> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public CrossBrowserStorageService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<CrossBrowserItem> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient);
        this.expirationInSeconds = configurationService.getSessionExpiry();
        this.nowClock = new NowClock(clock);
    }

    public void storeItem(CrossBrowserItem crossBrowserItem) {
        var item =
                crossBrowserItem.withTimeToLive(
                        nowClock.nowPlus(expirationInSeconds, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowException("Failed to store item", e);
        }
    }

    public Optional<String> getClientSessionId(State state) {
        Optional<CrossBrowserItem> clientSessionIdOpt = Optional.empty();
        try {
            clientSessionIdOpt = get(state.getValue());
        } catch (Exception e) {
            logAndThrowException("Failed to get item", e);
        }
        return clientSessionIdOpt
                .filter(s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond())
                .map(CrossBrowserItem::getClientSessionId);
    }

    private void logAndThrowException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new CrossBrowserStorageException(message);
    }
}
