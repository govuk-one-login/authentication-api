package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.oidc.entity.ClientRateLimitData;
import uk.gov.di.authentication.oidc.exceptions.ClientRateLimitDataException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.BaseDynamoService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class ClientRateLimitDataService extends BaseDynamoService<ClientRateLimitData> {

    private static final Logger LOG = LogManager.getLogger(ClientRateLimitDataService.class);
    private static final long TIME_TO_LIVE = 600;

    private final NowHelper.NowClock nowClock;

    public ClientRateLimitDataService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public ClientRateLimitDataService(ConfigurationService configurationService, Clock clock) {
        super(ClientRateLimitData.class, "Client-Rate-Limit", configurationService, true);
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public ClientRateLimitDataService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<ClientRateLimitData> dynamoDbTable,
            ConfigurationService configurationService) {
        this(dynamoDbClient, dynamoDbTable, configurationService, Clock.systemUTC());
    }

    public ClientRateLimitDataService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<ClientRateLimitData> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public void storeData(ClientRateLimitData clientRateLimitData) {
        var item =
                clientRateLimitData.withTimeToLive(
                        nowClock.nowPlus(TIME_TO_LIVE, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowRateLimitException(
                    "Failed to add client rate limit item", clientRateLimitData.getClientId(), e);
        }
    }

    public Optional<ClientRateLimitData> getData(String clientId, LocalDateTime periodStartTime) {
        try {
            return getWithConsistentRead(clientId, periodStartTime.toString())
                    .filter(s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        } catch (Exception e) {
            logAndThrowRateLimitException("Failed to get client rate limit item", clientId, e);
        }
        return Optional.empty();
    }

    private void logAndThrowRateLimitException(String message, String clientId, Exception e) {
        LOG.error("{}. Client ID: {}. Error message: {}", message, clientId, e.getMessage());
        throw new ClientRateLimitDataException(message);
    }
}
