package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.oidc.entity.SlidingWindowData;
import uk.gov.di.authentication.oidc.services.ClientRateLimitDataService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;

public class ClientRateLimitExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Client-Rate-Limit";
    public static final String CLIENT_ID_FIELD = "ClientId";
    public static final String PERIOD_START_TIME_FIELD = "PeriodStartTime";
    private ClientRateLimitDataService clientRateLimitDataService;
    private final ConfigurationService configurationService;

    public ClientRateLimitExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        clientRateLimitDataService = new ClientRateLimitDataService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        clientRateLimitDataService = new ClientRateLimitDataService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB, TABLE_NAME, CLIENT_ID_FIELD, Optional.of(PERIOD_START_TIME_FIELD));
    }

    @Override
    protected void createTables() {
        createTableWithPartitionAndSortKey(TABLE_NAME, CLIENT_ID_FIELD, PERIOD_START_TIME_FIELD);
    }

    public Optional<SlidingWindowData> getData(String clientId, LocalDateTime periodStartTime) {
        return clientRateLimitDataService.getData(clientId, periodStartTime);
    }

    public void increment(String clientId, LocalDateTime periodStartTime) {
        clientRateLimitDataService.increment(clientId, periodStartTime);
    }

    public void setClock(Clock clock) {
        clientRateLimitDataService = new ClientRateLimitDataService(configurationService, clock);
    }
}
