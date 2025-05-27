package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.StoredState;
import uk.gov.di.orchestration.shared.exceptions.StateStorageException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static java.time.Clock.fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StateStorageServiceTest {
    private static final State TEST_STATE = new State("TEST_STATE");
    private static final String TEST_SESSION_ID = "TEST_SESSION_ID";
    private static final String TEST_SESSION_ID_PREFIX = "SOME_STATE:";
    private static final String TEST_SESSION_ID_WITH_PREFIX =
            TEST_SESSION_ID_PREFIX + TEST_SESSION_ID;
    // 2025-05-27T14:21:28Z
    private static final long FIXED_TIMESTAMP = 1748355688L;
    private static final long MOCKED_TTL = 86400L;
    private static final Clock TEST_CLOCK =
            fixed(Instant.ofEpochSecond(FIXED_TIMESTAMP), ZoneId.systemDefault());
    private static final long VALID_TTL =
            Instant.ofEpochSecond(FIXED_TIMESTAMP).plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final Key PREFIXED_SESSION_ID_PARTITION_KEY =
            Key.builder().partitionValue(TEST_SESSION_ID_WITH_PREFIX).build();
    private static final GetItemEnhancedRequest SESSION_GET_REQUEST =
            GetItemEnhancedRequest.builder()
                    .key(PREFIXED_SESSION_ID_PARTITION_KEY)
                    .consistentRead(false)
                    .build();

    private final DynamoDbTable<StoredState> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private StateStorageService stateStorageService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(MOCKED_TTL);
        stateStorageService =
                new StateStorageService(dynamoDbClient, table, configurationService, TEST_CLOCK);
    }

    @Test
    void itCallsPutWithTheExpectedItemWhenCallingStoreState() {
        stateStorageService.storeState(TEST_SESSION_ID_PREFIX + TEST_SESSION_ID, TEST_STATE);
        var expectedItem =
                new StoredState(TEST_SESSION_ID_PREFIX + TEST_SESSION_ID)
                        .withState(TEST_STATE.getValue())
                        .withTtl(FIXED_TIMESTAMP + MOCKED_TTL);

        var putItemCaptor = ArgumentCaptor.forClass(StoredState.class);
        verify(table).putItem(putItemCaptor.capture());
        assertEquals(
                expectedItem.getPrefixedSessionId(),
                putItemCaptor.getValue().getPrefixedSessionId());
        assertEquals(expectedItem.getState(), putItemCaptor.getValue().getState());
        assertEquals(expectedItem.getTtl(), putItemCaptor.getValue().getTtl());
    }

    @Test
    void itReturnsTheStateValueWhenThereIsAValidItemStored() {
        withValidStoredState();

        var storedState = stateStorageService.getState(TEST_SESSION_ID_WITH_PREFIX);
        assertTrue(storedState.isPresent());
        assertEquals(TEST_STATE.getValue(), storedState.get().getValue());
    }

    @Test
    void itReturnsEmptyWhenExpiredStateStored() {
        withExpiredStoredState();

        var storedState = stateStorageService.getState(TEST_SESSION_ID_WITH_PREFIX);
        assertTrue(storedState.isPresent());
        assertEquals(TEST_STATE.getValue(), storedState.get().getValue());
    }

    @Test
    void itRethrowsErrorsWhenGettingAsStateStorageException() {
        withFailedGet();
        assertThrows(
                StateStorageException.class,
                () -> stateStorageService.getState(TEST_SESSION_ID_WITH_PREFIX));
    }

    @Test
    void itRethrowsErrorsWhenPuttingAsStateStorageException() {
        withFailedPut();
        assertThrows(
                StateStorageException.class,
                () -> stateStorageService.storeState(TEST_SESSION_ID_WITH_PREFIX, TEST_STATE));
    }

    private void withValidStoredState() {
        when(table.getItem(SESSION_GET_REQUEST)).thenReturn(getValidStoredState());
    }

    private void withExpiredStoredState() {
        when(table.getItem(SESSION_GET_REQUEST)).thenReturn(getExpiredStoredState());
    }

    private void withFailedPut() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(any(StoredState.class));
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));
    }

    private StoredState getValidStoredState() {
        return new StoredState(TEST_SESSION_ID_WITH_PREFIX)
                .withState(TEST_STATE.getValue())
                .withTtl(VALID_TTL);
    }

    private StoredState getExpiredStoredState() {
        return new StoredState(TEST_SESSION_ID_WITH_PREFIX)
                .withState(TEST_STATE.getValue())
                .withTtl(EXPIRED_TTL);
    }
}
