package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.exceptions.StateStorageException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StateStorageServiceTest extends BaseDynamoServiceTest<StateItem> {
    private static final String PREFIXED_SESSION_ID = "state:test-session-id";
    private static final State STATE = new State();
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final GetItemEnhancedRequest STATE_GET_REQUEST =
            getRequestFor(PREFIXED_SESSION_ID);
    private StateStorageService stateStorageService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        stateStorageService = new StateStorageService(dynamoDbClient, table, configurationService);
    }

    @Test
    void shouldStoreState() {
        stateStorageService.storeState(PREFIXED_SESSION_ID, STATE.getValue());

        var captor = ArgumentCaptor.forClass(StateItem.class);
        verify(table).putItem(captor.capture());
        assertEquals(PREFIXED_SESSION_ID, captor.getValue().getPrefixedSessionId());
        assertEquals(STATE.getValue(), captor.getValue().getState());
    }

    @Test
    void shouldThrowIfStoringStateFails() {
        withFailedPut();
        assertThrows(
                StateStorageException.class,
                () -> stateStorageService.storeState(PREFIXED_SESSION_ID, STATE.getValue()));
    }

    @Test
    void shouldGetStateByPrefixedSessionId() {
        var expectedStateItem = withValidStateItemInDynamo();
        var actualStateItem = stateStorageService.getState(PREFIXED_SESSION_ID);
        verify(table).getItem(STATE_GET_REQUEST);
        assertTrue(actualStateItem.isPresent());
        assertEquals(expectedStateItem, actualStateItem.get());
    }

    @Test
    void shouldNotGetStateIfTtlHasExpired() {
        withExpiredStateItem();
        var actualStateItem = stateStorageService.getState(PREFIXED_SESSION_ID);
        assertTrue(actualStateItem.isEmpty());
    }

    @Test
    void shouldNotGetStateIfStateDoesNotExist() {
        var actualStateItem = stateStorageService.getState(PREFIXED_SESSION_ID);
        assertTrue(actualStateItem.isEmpty());
    }

    @Test
    void shouldThrowIfGettingStateFails() {
        withFailedGet();
        assertThrows(
                StateStorageException.class,
                () -> stateStorageService.getState(PREFIXED_SESSION_ID));
    }

    private void withFailedPut() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(any(StateItem.class));
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get item from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));
    }

    private StateItem withValidStateItemInDynamo() {
        var stateItem = createValidStateItem();
        when(table.getItem(STATE_GET_REQUEST)).thenReturn(stateItem);
        return stateItem;
    }

    private void withExpiredStateItem() {
        var stateItem =
                new StateItem()
                        .withPrefixedSessionId(PREFIXED_SESSION_ID)
                        .withState(STATE.getValue())
                        .withTimeToLive(EXPIRED_TTL);
        when(table.getItem(STATE_GET_REQUEST)).thenReturn(stateItem);
    }

    private StateItem createValidStateItem() {
        return new StateItem()
                .withPrefixedSessionId(PREFIXED_SESSION_ID)
                .withState(STATE.getValue())
                .withTimeToLive(VALID_TTL);
    }
}
