package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;

import java.util.List;
import java.util.Optional;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.CONDITIONAL_MOVE;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.Action.MOVE_TO_3;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_1;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_2;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_3;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_4;
import static uk.gov.di.authentication.shared.state.StateMachineTest.State.STATE_5;

public class StateMachineTest {

    enum State {
        STATE_1,
        STATE_2,
        STATE_3,
        STATE_4,
        STATE_5
    }

    enum Action {
        MOVE_TO_2,
        MOVE_TO_3,
        CONDITIONAL_MOVE
    }

    private final Condition<Boolean> testCondition =
            new Condition<Boolean>() {
                @Override
                public boolean isMet(Optional<Boolean> context) {
                    return context.get().booleanValue();
                }
            };

    private final StateMachine<State, Action, Boolean> testStateMachine =
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
                                                    CONDITIONAL_MOVE, STATE_5, new Default<>())))));

    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            StateMachine.userJourneyStateMachine();

    @Test
    public void returnsCorrectNextStateForSimpleTransition() {
        assertThat(testStateMachine.transition(STATE_1, MOVE_TO_2), equalTo(STATE_2));
        assertThat(testStateMachine.transition(STATE_2, MOVE_TO_3), equalTo(STATE_3));
    }

    @Test
    public void returnsCorrectNextStateForConditionalTransition() {
        assertThat(
                testStateMachine.transition(STATE_3, CONDITIONAL_MOVE, Boolean.TRUE),
                equalTo(STATE_4));
    }

    @Test
    public void returnsDefaultNextStateForConditionalTransitionWhenNoOtherConditionMatches() {
        assertThat(
                testStateMachine.transition(STATE_3, CONDITIONAL_MOVE, Boolean.FALSE),
                equalTo(STATE_5));
    }

    @Test
    public void throwsInvalidStateTransitionExceptionForMissingTransition() {
        assertThrows(
                StateMachine.InvalidStateTransitionException.class,
                () -> testStateMachine.transition(STATE_1, MOVE_TO_3));
    }

    @Test
    public void returns_MFA_SMS_CODE_SENT_WhenUserEntersPasswordAgain() {
        final SessionState nextState =
                stateMachine.transition(
                        MFA_SMS_CODE_SENT, SessionAction.USER_ENTERED_VALID_CREDENTIALS);
        assertThat(nextState, equalTo(MFA_SMS_CODE_SENT));
    }
}
