package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Optional;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.ACTION_COMMON_TO_SOME_STATES;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.ACTION_THAT_CAN_OCCUR_AT_ANY_STATE;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.CONDITIONAL_MOVE;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_3;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_1;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_3;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_4;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_5;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_6;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_7;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class StateMachineTest {

    enum State {
        STATE_1,
        STATE_2,
        STATE_3,
        STATE_4,
        STATE_5,
        STATE_6,
        STATE_7
    }

    enum Action {
        MOVE_TO_2,
        MOVE_TO_3,
        CONDITIONAL_MOVE,
        ACTION_THAT_CAN_OCCUR_AT_ANY_STATE,
        ACTION_COMMON_TO_SOME_STATES
    }

    private final Condition<Boolean> testCondition = Optional::get;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(StateMachine.class);

    @AfterEach
    public void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining("unknown"))));
    }

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

    @Test
    void builderReturnsCorrectlyConfiguredMachine() {
        final List<Transition<State, Action, Boolean>> A_TRANSITION_INCLUDE =
                List.of(on(ACTION_COMMON_TO_SOME_STATES).then(STATE_7).build());

        var builtMachine =
                StateMachine.<State, Action, Boolean>builder()
                        .when(STATE_1)
                        .include(A_TRANSITION_INCLUDE)
                        .allow(on(MOVE_TO_2).then(STATE_2))
                        .when(STATE_2)
                        .include(A_TRANSITION_INCLUDE)
                        .allow(
                                on(CONDITIONAL_MOVE).ifCondition(testCondition).then(STATE_4),
                                on(CONDITIONAL_MOVE)
                                        .ifCondition(testCondition)
                                        .then(STATE_5)
                                        .byDefault(),
                                on(MOVE_TO_3).then(STATE_3))
                        .atAnyState()
                        .allow(on(ACTION_THAT_CAN_OCCUR_AT_ANY_STATE).then(STATE_6))
                        .build();

        assertThat(builtMachine.transition(STATE_1, MOVE_TO_2, true), equalTo(STATE_2));
        assertThat(
                builtMachine.transition(STATE_1, ACTION_COMMON_TO_SOME_STATES, true),
                equalTo(STATE_7));
        assertThat(
                builtMachine.transition(STATE_2, ACTION_COMMON_TO_SOME_STATES, true),
                equalTo(STATE_7));
        assertThat(builtMachine.transition(STATE_2, CONDITIONAL_MOVE, false), equalTo(STATE_5));
        assertThat(builtMachine.transition(STATE_2, MOVE_TO_3, false), equalTo(STATE_3));
        assertThat(
                builtMachine.transition(STATE_1, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE, true),
                equalTo(STATE_6));
        assertThat(
                builtMachine.transition(STATE_2, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE, true),
                equalTo(STATE_6));
        assertThat(
                builtMachine.transition(STATE_3, ACTION_THAT_CAN_OCCUR_AT_ANY_STATE, true),
                equalTo(STATE_6));
        assertThrows(
                StateMachine.InvalidStateTransitionException.class,
                () -> builtMachine.transition(STATE_3, ACTION_COMMON_TO_SOME_STATES, true));
    }

    private static Transition.Builder<State, Action, Boolean> on(Action action) {
        return Transition.<State, Action, Boolean>builder().on(action);
    }
}
