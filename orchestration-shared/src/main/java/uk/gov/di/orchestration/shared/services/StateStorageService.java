package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.StoredState;
import uk.gov.di.orchestration.shared.exceptions.StateStorageException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class StateStorageService extends BaseDynamoService<StoredState> {
    private static final Logger LOG = LogManager.getLogger(StateStorageService.class);
    private final long timeToLive;
    private final NowHelper.NowClock nowClock;

    public StateStorageService(ConfigurationService configurationService) {
        super(StoredState.class, "State-Storage", configurationService, true);
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowHelper.NowClock(Clock.systemUTC());
    }

    public StateStorageService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<StoredState> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public void storeState(String prefixedSessionId, State state) {
        LOG.info("Storing State in dynamo");

        try {
            put(
                    new StoredState(prefixedSessionId)
                            .withState(state.getValue())
                            .withTtl(
                                    nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                            .toInstant()
                                            .getEpochSecond()));
        } catch (Exception e) {
            LOG.error("Failed to store state in Dynamo: {}", e.getMessage());
            throw new StateStorageException("Failed to store state in Dynamo");
        }
    }

    public Optional<State> getState(String prefixedSessionId) {
        Optional<StoredState> storedState;

        try {
            storedState = get(prefixedSessionId);
        } catch (Exception e) {
            LOG.error("Failed to fetch state from Dynamo: {}", e.getMessage());
            throw new StateStorageException("Failed to fetch state from Dynamo");
        }

        return storedState
                .filter(s -> s.getTtl() > nowClock.now().toInstant().getEpochSecond())
                .map(StoredState::getState)
                .map(State::parse);
    }
}
