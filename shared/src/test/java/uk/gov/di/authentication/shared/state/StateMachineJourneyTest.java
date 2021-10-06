package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;

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

    @Test
    public void returns_EMAIL_MAX_CODES_SENT_WhenUserEntersTooManyCodes() {
        final SessionState nextState =
                stateMachine.transition(
                        NEW, SessionAction.SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES);
        assertThat(nextState, equalTo(EMAIL_MAX_CODES_SENT));
    }

    @Test
    public void returns_EMAIL_MAX_CODES_SENT_WhenUserRequestsTooManyCodes() {
        final SessionState nextState =
                stateMachine.transition(
                        USER_NOT_FOUND,
                        SessionAction.SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES);
        assertThat(nextState, equalTo(EMAIL_MAX_CODES_SENT));
    }

    @Test
    public void returns_VERIFY_EMAIL_CODE_SENT_WhenUserSendsAnotherCode() {
        final SessionState nextState =
                stateMachine.transition(
                        VERIFY_EMAIL_CODE_SENT,
                        SessionAction.SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE);
        assertThat(nextState, equalTo(VERIFY_EMAIL_CODE_SENT));
    }
}
