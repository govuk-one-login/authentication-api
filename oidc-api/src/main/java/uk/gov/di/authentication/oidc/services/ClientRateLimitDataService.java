package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.oidc.entity.SlidingWindowData;
import uk.gov.di.authentication.oidc.exceptions.ClientRateLimitDataException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.BaseDynamoService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class ClientRateLimitDataService extends BaseDynamoService<SlidingWindowData> {

    private static final Logger LOG = LogManager.getLogger(ClientRateLimitDataService.class);
    private static final long TIME_TO_LIVE = 600;

    private final NowHelper.NowClock nowClock;

    public ClientRateLimitDataService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public ClientRateLimitDataService(ConfigurationService configurationService, Clock clock) {
        super(SlidingWindowData.class, "Client-Rate-Limit", configurationService, true);
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public ClientRateLimitDataService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<SlidingWindowData> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public ClientRateLimitDataService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<SlidingWindowData> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public void storeData(SlidingWindowData slidingWindowData) {
        var item =
                slidingWindowData.withTimeToLive(
                        nowClock.nowPlus(TIME_TO_LIVE, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowRateLimitException(
                    "Failed to add client rate limit item", slidingWindowData.getClientId(), e);
        }
    }

    public Optional<SlidingWindowData> getData(String clientId, LocalDateTime periodStartTime) {
        try {
            return getWithConsistentRead(clientId, periodStartTime.toString())
                    .filter(s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        } catch (Exception e) {
            logAndThrowRateLimitException("Failed to get client rate limit item", clientId, e);
        }
        return Optional.empty();
    }

    /**
     * This method makes a DynamoDB UpdateItem call. This can result in one of 2 things:
     *
     * <ol>
     *   <li>If no data exists for the given clientId and periodStartTime, then a new entry will be
     *       created with a request count of 1
     *   <li>If data does exist for the given clientId and periodStartTime, then the {@link
     *       SlidingWindowData#getRequestCount() request count} will be incremented by 1.
     * </ol>
     *
     * <p>The incrementing is handled by using an atomic counter. More information can be found
     * below.
     *
     * <p>If an error occurs when trying to perform the update, it will be silently ignored. This is
     * to ensure we don't over-increment, as this could lead to a client being rate limited before
     * they reach their actual rate limit.
     *
     * @param clientId The client ID
     * @param periodStartTime The period start time
     * @see <a
     *     href="https://aws.amazon.com/blogs/database/implement-resource-counters-with-amazon-dynamodb/">Information
     *     on atomic counters</a>
     */
    public void increment(String clientId, LocalDateTime periodStartTime) {
        try {
            var clientRateLimitData =
                    new SlidingWindowData(clientId, periodStartTime)
                            .withTimeToLive(
                                    nowClock.nowPlus(TIME_TO_LIVE, ChronoUnit.SECONDS)
                                            .toInstant()
                                            .getEpochSecond());
            update(clientRateLimitData);
        } catch (Exception e) {
            LOG.info(
                    "Could not increment request count for client {}. Reason: {}",
                    clientId,
                    e.getMessage());
        }
    }

    private void logAndThrowRateLimitException(String message, String clientId, Exception e) {
        LOG.error("{}. Client ID: {}. Error message: {}", message, clientId, e.getMessage());
        throw new ClientRateLimitDataException(message);
    }
}
