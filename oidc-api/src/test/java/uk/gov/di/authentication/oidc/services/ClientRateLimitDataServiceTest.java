package uk.gov.di.authentication.oidc.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.authentication.oidc.entity.SlidingWindowData;
import uk.gov.di.authentication.oidc.exceptions.ClientRateLimitDataException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.TEST_CLIENT_ID;

class ClientRateLimitDataServiceTest extends BaseDynamoServiceTest<SlidingWindowData> {
    private static final LocalDateTime TEST_PERIOD_START =
            LocalDateTime.parse("2025-09-14T13:00:00");
    private static final Key TEST_PARTITION_AND_SORT_KEY =
            Key.builder()
                    .partitionValue(TEST_CLIENT_ID)
                    .sortValue(TEST_PERIOD_START.toString())
                    .build();
    private static final GetItemEnhancedRequest RATE_LIMIT_DATA_GET_REQUEST =
            GetItemEnhancedRequest.builder()
                    .key(TEST_PARTITION_AND_SORT_KEY)
                    .consistentRead(true)
                    .build();
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private ClientRateLimitDataService clientRateLimitDataService;

    @BeforeEach
    void setup() {
        clientRateLimitDataService = new ClientRateLimitDataService(dynamoDbClient, table);
    }

    @Test
    void shouldGetRateLimitData() {
        withValidClientRateLimitData();
        var slidingWindowData =
                clientRateLimitDataService.getData(TEST_CLIENT_ID, TEST_PERIOD_START);
        assertTrue(slidingWindowData.isPresent());
        assertEquals(TEST_CLIENT_ID, slidingWindowData.get().getClientId());
    }

    @Test
    void shouldThrowWhenFailingToGetRateLimitData() {
        withFailedGet();
        assertThrows(
                ClientRateLimitDataException.class,
                () -> clientRateLimitDataService.getData(TEST_CLIENT_ID, TEST_PERIOD_START));
    }

    @Test
    void shouldNotGetRateLimitDataWhenNoRateLimitDataExistsForClient() {
        var clientSession = clientRateLimitDataService.getData(TEST_CLIENT_ID, TEST_PERIOD_START);
        assertTrue(clientSession.isEmpty());
    }

    private SlidingWindowData withValidClientRateLimitData() {
        var existingSlidingWindowData =
                new SlidingWindowData(TEST_CLIENT_ID, TEST_PERIOD_START).withTimeToLive(VALID_TTL);
        when(table.getItem(RATE_LIMIT_DATA_GET_REQUEST)).thenReturn(existingSlidingWindowData);
        return existingSlidingWindowData;
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));
    }
}
