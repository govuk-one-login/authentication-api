package uk.gov.di.authentication.shared.state;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_REQUESTS_BLOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;

public class StateMachineJourneyTest {

    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            StateMachine.userJourneyStateMachine();

    private final Session session = new Session(IdGenerator.generate());

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

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterWaitingForAMfaCodeWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        MFA_SMS_CODE_SENT,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterReachingMfaLimitWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        MFA_SMS_MAX_CODES_SENT,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterBeingBlockedFromGeneratingMfaCodesWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        MFA_CODE_REQUESTS_BLOCKED,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterEnteringAnInvalidMfaCodeWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        MFA_CODE_NOT_VALID,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterEnteringAnInvalidMfaCodeTooManyTimesWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        MFA_CODE_MAX_RETRIES_REACHED,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void
            returns_UPLIFT_REQUIRED_CM_WhenUserStartsNewJourneyAfterReachingConsentPageWhilstUplifting() {
        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(null, null, null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .build();
        final SessionState nextState =
                stateMachine.transition(
                        CONSENT_REQUIRED,
                        SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY,
                        userContext);
        assertThat(nextState, equalTo(UPLIFT_REQUIRED_CM));
    }
}
