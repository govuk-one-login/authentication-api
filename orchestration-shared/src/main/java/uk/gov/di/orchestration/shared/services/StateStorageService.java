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

    public void storeState(String prefixedSessionId, String state) {
        var item =
                new StateItem(prefixedSessionId)
                        .withState(state)
                        .withTimeToLive(
                                nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowStateStorageException("Failed to add StateItem", prefixedSessionId, e);
        }
    }

    public Optional<StateItem> getState(String prefixedSessionId) {
        try {
            return get(prefixedSessionId)
                    .filter(s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        } catch (Exception e) {
            logAndThrowStateStorageException("Failed to get StateItem", prefixedSessionId, e);
        }
        return Optional.empty();
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
