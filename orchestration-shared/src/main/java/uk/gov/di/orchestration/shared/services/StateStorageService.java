package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.exceptions.StateStorageException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class StateStorageService extends BaseDynamoService<StateItem> {
    private static final Logger LOG = LogManager.getLogger(StateStorageService.class);
    private final NowHelper.NowClock nowClock;

    private final long timeToLive;

    public StateStorageService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public StateStorageService(ConfigurationService configurationService, Clock clock) {
        super(StateItem.class, "State-Storage", configurationService, true);
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public StateStorageService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<StateItem> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public StateStorageService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<StateItem> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public void storeState(StateItem stateItem) {
        var item =
                stateItem.withTimeToLive(
                        nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowStateStorageException(
                    "Failed to add StateItem", stateItem.getPrefixedSessionId(), e);
        }
    }

    public Optional<StateItem> getState(String prefixedSessionId) {
        Optional<StateItem> stateItem = Optional.empty();
        try {
            stateItem = get(prefixedSessionId);
        } catch (Exception e) {
            logAndThrowStateStorageException("Failed to get StateItem", prefixedSessionId, e);
        }
        if (stateItem.isEmpty()) {
            LOG.info("No state item found with prefixedSessionId {}", prefixedSessionId);
            return stateItem;
        }

        Optional<StateItem> validStateItem =
                stateItem.filter(
                        s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        if (validStateItem.isEmpty()) {
            LOG.info("State item with expired TTL found. Session ID: {}", prefixedSessionId);
        }
        return validStateItem;
    }

    private void logAndThrowStateStorageException(
            String message, String prefixedSessionId, Exception e) {
        LOG.error(
                "{}. prefixedSessionId: {}. Error message: {}",
                message,
                prefixedSessionId,
                e.getMessage());
        throw new StateStorageException(message);
    }
}
