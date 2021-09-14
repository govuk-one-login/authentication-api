package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;

import java.util.List;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_3;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_1;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_3;

public class StateMachineTest {

    enum State {
        STATE_1,
        STATE_2,
        STATE_3,
    }

    enum Action {
        MOVE_TO_2,
        MOVE_TO_3
    }

    StateMachine<State, Action, Object> stateMachine =
            new StateMachine<>(
                    ofEntries(
                            entry(STATE_1, List.of(new Transition<>(MOVE_TO_2, STATE_2))),
                            entry(STATE_2, List.of(new Transition<>(MOVE_TO_3, STATE_3)))));

    @Test
    public void returnsCorrectNextStateForValidTransition() {
        assertThat(stateMachine.transition(STATE_1, MOVE_TO_2), equalTo(STATE_2));
        assertThat(stateMachine.transition(STATE_2, MOVE_TO_3), equalTo(STATE_3));
    }

    @Test
    public void returnsFalseForMissingTransition() {
        assertThrows(
                StateMachine.InvalidStateTransitionException.class,
                () -> stateMachine.transition(STATE_1, MOVE_TO_3));
    }
}
