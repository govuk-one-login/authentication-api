package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessTokenServiceTest {
    private final DynamoDbTable<AccessTokenStore> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AccessTokenStore accessTokenStore = mock(AccessTokenStore.class);
    public AccessTokenService accessTokenService;
    private final Key testPartitionKey = Key.builder().partitionValue("test").build();
    private static final String TEST_ENVIRONMENT = "test-environment";
    private static final String TEST_PARTITION = "test";

    @BeforeEach
    void beforeEach() {
        accessTokenService =
                new AccessTokenService(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoDbClient,
                        table,
                        100000L);

        when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
    }

    @Test
    void shouldCallGetItemTwiceIfInitialQueryReturnsNull() {
        when(table.getItem(testPartitionKey)).thenReturn(null);

        accessTokenService.get(TEST_PARTITION);

        verify(table, times(1)).getItem(any(Key.class));
        verify(table, times(1)).getItem(any(GetItemEnhancedRequest.class));
    }

    @Test
    void shouldIncrementCountersWhenInitialQueryFailsAndConsistentReadQuerySucceeds() {
        when(table.getItem(testPartitionKey)).thenReturn(null);
        when(table.getItem(any(GetItemEnhancedRequest.class))).thenReturn(accessTokenStore);

        accessTokenService.get(TEST_PARTITION);

        verify(cloudwatchMetricsService, times(1))
                .incrementCounter(
                        "AccessTokenServiceInitialQueryAttempt",
                        Map.of("Environment", "test-environment"));
        verify(cloudwatchMetricsService, times(1))
                .incrementCounter(
                        "AccessTokenServiceConsistentReadQueryAttempt",
                        Map.of("Environment", "test-environment"));
        verify(cloudwatchMetricsService, times(1))
                .incrementCounter(
                        "AccessTokenServiceConsistentReadQueryAttemptSuccess",
                        Map.of("Environment", "test-environment"));
    }

    @Test
    void shouldIncrementInitialAttemptAndInitialSuccessCounterWhenGetSucceeds() {
        when(table.getItem(testPartitionKey)).thenReturn(accessTokenStore);

        accessTokenService.get(TEST_PARTITION);

        verify(cloudwatchMetricsService, times(1))
                .incrementCounter(
                        "AccessTokenServiceInitialQueryAttempt",
                        Map.of("Environment", "test-environment"));
        verify(cloudwatchMetricsService, times(1))
                .incrementCounter(
                        "AccessTokenServiceInitialQuerySuccess",
                        Map.of("Environment", "test-environment"));
    }
}
