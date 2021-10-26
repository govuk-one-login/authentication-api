package uk.gov.di.authentication.shared.state.journeys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.CLIENT_ID;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateAuthRequest;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateLowLevelVectorOfTrust;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateUserProfile;

public class EmailVerificationJourneyTest {
    private final ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

    private final Session session = new Session(IdGenerator.generate());

    private StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getTermsAndConditionsVersion()).thenReturn("1.0");

        stateMachine = StateMachine.userJourneyStateMachine(mockConfigurationService);
    }

    @Test
    public void testCanVerifyEmail() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE,
                                EMAIL_CODE_VERIFIED));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void testCanReachBlockedStatusIfTooManyCodesAreRequested() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES,
                                EMAIL_MAX_CODES_SENT));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void testCanReachBlockedByRequestingTooManyCodesButEnterANewEmailAddressToStartAgain() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES,
                                EMAIL_MAX_CODES_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void testCanReachBlockedStatusIfIncorrectCodeIsEnteredTooManyTimes() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                EMAIL_CODE_NOT_VALID),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                                EMAIL_CODE_MAX_RETRIES_REACHED));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void
            testCanReachBlockedByIncorrectCodeTooManyTimesButEnterANewEmailAddressToStartAgain() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                EMAIL_CODE_NOT_VALID),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                                EMAIL_CODE_MAX_RETRIES_REACHED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void
            testCanReachBlockedByIncorrectCodeTooManyTimesAndStartANewJourneyWithBrowserBackButtonAndReachBlocked() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                EMAIL_CODE_NOT_VALID),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                                EMAIL_CODE_MAX_RETRIES_REACHED),
                        new JourneyTransition(userContext, USER_HAS_STARTED_A_NEW_JOURNEY, NEW),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                                EMAIL_CODE_MAX_RETRIES_REACHED));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }

    @Test
    public void
            testCanReachBlockedByRequestingTooManyCodesAndStartANewJourneyWithBrowserBackButtonAndReachBlocked() {
        UserProfile userProfile =
                generateUserProfile(true, "1.0", new HashSet<String>(Collections.emptyList()));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                VERIFY_EMAIL_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES,
                                EMAIL_MAX_CODES_SENT),
                        new JourneyTransition(userContext, USER_HAS_STARTED_A_NEW_JOURNEY, NEW),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES,
                                EMAIL_MAX_CODES_SENT));

        SessionState currentState = NEW;

        for (JourneyTransition transition : transitions) {
            currentState =
                    stateMachine.transition(
                            currentState,
                            transition.getSessionAction(),
                            transition.getUserContext());
            assertThat(currentState, equalTo(transition.getExpectedSessionState()));
        }
    }
}
