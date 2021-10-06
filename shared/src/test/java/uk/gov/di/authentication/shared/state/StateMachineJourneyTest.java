package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;

public class StateMachineJourneyTest {

    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            StateMachine.userJourneyStateMachine();

    @Test
    public void returns_MFA_SMS_CODE_SENT_WhenUserEntersPasswordAgain() {
        final SessionState nextState =
                stateMachine.transition(
                        MFA_SMS_CODE_SENT, SessionAction.USER_ENTERED_VALID_CREDENTIALS);
        assertThat(nextState, equalTo(MFA_SMS_CODE_SENT));
    }
}
