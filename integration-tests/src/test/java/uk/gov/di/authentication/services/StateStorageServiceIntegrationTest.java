package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.exceptions.StateStorageException;
import uk.gov.di.orchestration.sharedtest.extensions.StateStorageExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static java.time.Clock.fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StateStorageServiceIntegrationTest {
    private static final String PREFIXED_SESSION_ID = "test-prefixed-session-id";
    private static final State STATE = new State();

    @RegisterExtension
    protected static final StateStorageExtension stateStorageExtension =
            new StateStorageExtension();

    @BeforeEach
    void setup() {
        stateStorageExtension.setClock(Clock.systemUTC());
    }

    @Test
    void shouldThrowWhenFailingToStoreState() {
        var invalidStateItem = new StateItem(null);
        assertThrows(
                StateStorageException.class,
                () ->
                        stateStorageExtension.storeState(
                                invalidStateItem.getPrefixedSessionId(),
                                invalidStateItem.getState()));
    }

    @Test
    void shouldReturnEmptyOptionalWhenStateWithPrefixedSessionIdDoesNotExist() {
        var stateItem = stateStorageExtension.getState("not-a-prefixed-session-id");
        assertTrue(stateItem.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToGetStateByPrefixedSessionId() {
        assertThrows(StateStorageException.class, () -> stateStorageExtension.getState(null));
    }

    @Test
    void shouldStoreAndRetrieveState() {
        stateStorageExtension.storeState(PREFIXED_SESSION_ID, STATE.getValue());

        var actualStateItemOpt = stateStorageExtension.getState(PREFIXED_SESSION_ID);
        assertTrue(actualStateItemOpt.isPresent());
        var actualStateItem = actualStateItemOpt.get();
        assertEquals(PREFIXED_SESSION_ID, actualStateItem.getPrefixedSessionId());
        assertEquals(STATE.getValue(), actualStateItem.getState());
    }

    @Test
    void shouldNotRetrieveStateIfTtlHasExpired() {
        fixTime(Instant.parse("2025-08-26T16:00:00Z"));
        stateStorageExtension.storeState(PREFIXED_SESSION_ID, STATE.getValue());

        fixTime(Instant.parse("2025-08-26T17:01:00Z"));
        var actualStateItem = stateStorageExtension.getState(PREFIXED_SESSION_ID);
        assertTrue(actualStateItem.isEmpty());
    }

    private static void fixTime(Instant time) {
        stateStorageExtension.setClock(fixed(time, ZoneId.systemDefault()));
    }
}
