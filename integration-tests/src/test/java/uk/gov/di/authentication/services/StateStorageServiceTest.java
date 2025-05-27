package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.sharedtest.extensions.StateStorageExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StateStorageServiceTest {
    private static final State STATE = new State();
    private static final String SESSION_ID = "Session-ID";
    private static final String PREFIX = "TEST_STATE:";

    @RegisterExtension
    protected static final StateStorageExtension stateStorageExtension =
            new StateStorageExtension();

    @Test
    void itShouldFetchStateFromDynamo() {
        withExistingState();
        var state = stateStorageExtension.getStateFromDyamo(PREFIX + SESSION_ID);
        assertTrue(state.isPresent());
        assertEquals(STATE, state.get());
    }

    @Test
    void itReturnsEmptyForUnknownSessionId() {
        var state = stateStorageExtension.getStateFromDyamo(PREFIX + IdGenerator.generate());
        assertFalse(state.isPresent());
    }

    @Test
    void itPutsStateIntoDynamo() {
        var sessionId = IdGenerator.generate();
        var state = new State();

        stateStorageExtension.addStateToDynamo(PREFIX + sessionId, state);

        var fetchedState = stateStorageExtension.getStateFromDyamo(PREFIX + sessionId);
        assertTrue(fetchedState.isPresent());
        assertEquals(state, fetchedState.get());
    }

    private void withExistingState() {
        stateStorageExtension.addStateToDynamo(PREFIX + SESSION_ID, STATE);
    }
}
