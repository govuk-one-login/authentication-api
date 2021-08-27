package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.StateMachineTest.State.STATE_1;
import static uk.gov.di.authentication.shared.helpers.StateMachineTest.State.STATE_2;
import static uk.gov.di.authentication.shared.helpers.StateMachineTest.State.STATE_3;

public class StateMachineTest {

    enum State {
        STATE_1,
        STATE_2,
        STATE_3,
    }

    @Test
    public void returnsTrueForValidTransition() {
        var stateMachine = new StateMachine<>(Map.of(STATE_1, List.of(STATE_2)));

        assertTrue(stateMachine.isValidTransition(STATE_1, STATE_2));
    }

    @Test
    public void returnsFalseForValidTransition() {
        var stateMachine = new StateMachine<>(Map.of(STATE_1, List.of(STATE_2)));

        assertFalse(stateMachine.isValidTransition(STATE_2, STATE_1));
    }

    @Test
    public void returnsFalseForMissingTransition() {
        var stateMachine = new StateMachine<>(Map.of(STATE_1, List.of(STATE_2)));

        assertFalse(stateMachine.isValidTransition(STATE_3, STATE_1));
    }
}
