package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.*;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.*;

public class StateMachineTest {

    enum State {
        STATE_1,
        STATE_2,
        STATE_3,
        STATE_4,
        STATE_5,
        STATE_6
    }

    enum Action {
        MOVE_TO_2,
        MOVE_TO_3,
        CONDITIONAL_MOVE,
        ACTION_THAT_CAN_OCCUR_AT_ANY_STATE
    }

    private final Condition<Boolean> testCondition =
            new Condition<Boolean>() {
                @Override
                public boolean isMet(Optional<Boolean> context) {
                    return context.get().booleanValue();
                }
            };

    private final StateMachine<State, Action, Boolean> stateMachine =
            new StateMachine<>(
                    ofEntries(
                            entry(STATE_1, List.of(new Transition<>(MOVE_TO_2, STATE_2))),
                            entry(STATE_2, List.of(new Transition<>(MOVE_TO_3, STATE_3))),
                            entry(
                                    STATE_3,
                                    List.of(
                                            new Transition<>(
                                                    CONDITIONAL_MOVE, STATE_4, testCondition),
                                            new Transition<>(
                                                    CONDITIONAL_MOVE, STATE_5, new Default<>())))),
                    List.of(new Transition<>(Action.ACTION_THAT_CAN_OCCUR_AT_ANY_STATE, STATE_6)));

    @Test
    public void returnsCorrectNextStateForSimpleTransition() {
        assertThat(stateMachine.transition(STATE_1, MOVE_TO_2), equalTo(STATE_2));
        assertThat(stateMachine.transition(STATE_2, MOVE_TO_3), equalTo(STATE_3));
    }

    @Test
    public void returnsCorrectNextStateForConditionalTransition() {
        assertThat(
                stateMachine.transition(STATE_3, CONDITIONAL_MOVE, Boolean.TRUE), equalTo(STATE_4));
    }

    @Test
    public void returnsDefaultNextStateForConditionalTransitionWhenNoOtherConditionMatches() {
        assertThat(
                stateMachine.transition(STATE_3, CONDITIONAL_MOVE, Boolean.FALSE),
                equalTo(STATE_5));
    }

    @Test
    public void throwsInvalidStateTransitionExceptionForMissingTransition() {
        assertThrows(
                StateMachine.InvalidStateTransitionException.class,
                () -> stateMachine.transition(STATE_1, MOVE_TO_3));
    }

    @Test
    void returnsCorrectNextStateWhenUsingAnAnyStateTransition() {
        assertThat(
                stateMachine.transition(STATE_1, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
        assertThat(
                stateMachine.transition(STATE_2, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
        assertThat(
                stateMachine.transition(STATE_3, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
        assertThat(
                stateMachine.transition(STATE_4, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
        assertThat(
                stateMachine.transition(STATE_5, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
        assertThat(
                stateMachine.transition(STATE_6, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE),
                equalTo(STATE_6));
    }
}
