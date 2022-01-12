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
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_RESET_PASSWORD_LINK;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionState.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.CLIENT_ID;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateAuthRequest;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateLowLevelVectorOfTrust;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateUserProfile;

public class ForgottenPasswordJourneyTest {
    private final ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

    private final Session session = new Session(IdGenerator.generate());

    private StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getTermsAndConditionsVersion()).thenReturn("1.0");

        stateMachine = StateMachine.userJourneyStateMachine(mockConfigurationService);
    }

    @Test
    public void testCanReachForgottenPassword() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "1.0",
                        new HashSet<String>(
                                Arrays.asList(
                                        "phone_number",
                                        "phone_number_verified",
                                        "email",
                                        "email_verified",
                                        "sub")));

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
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                ACCOUNT_TEMPORARILY_LOCKED));

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
            testCanReachForgottenPasswordAndUseBrowserBackToAttemptSignInWithPhoneVerification() {
        UserProfile userProfile =
                generateUserProfile(
                                true,
                                "1.0",
                                new HashSet<String>(
                                        Arrays.asList(
                                                "phone_number", "email", "email_verified", "sub")))
                        .setPhoneNumberVerified(false);

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
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                                RESET_PASSWORD_LINK_SENT),
                        new JourneyTransition(
                                userContext, USER_ENTERED_VALID_CREDENTIALS, TWO_FACTOR_REQUIRED));

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
    public void testCanReachForgottenPasswordAndUseBrowserBackToAttemptSignInWithUpdatedTandC() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "0.9",
                        new HashSet<String>(
                                Arrays.asList(
                                        "phone_number",
                                        "phone_number_verified",
                                        "email",
                                        "email_verified",
                                        "sub")));

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
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                                RESET_PASSWORD_LINK_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_VALID_CREDENTIALS,
                                UPDATED_TERMS_AND_CONDITIONS));

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
    public void testCanReachForgottenPasswordAndUseBrowserBackToAttemptSignInWithoutMfa() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "1.0",
                        new HashSet<String>(
                                Arrays.asList(
                                        "phone_number",
                                        "phone_number_verified",
                                        "email",
                                        "email_verified",
                                        "sub")));

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
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                                RESET_PASSWORD_LINK_SENT),
                        new JourneyTransition(
                                userContext, USER_ENTERED_VALID_CREDENTIALS, AUTHENTICATED));

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
    public void testCanReachForgottenPasswordAndUseBrowserBackToAttemptSignInWithConsentRequired() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "1.0",
                        new HashSet<String>(
                                Arrays.asList("phone_number_verified", "email_verified", "sub")));

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
                        .withClient(
                                new ClientRegistry()
                                        .setClientID(CLIENT_ID.toString())
                                        .setConsentRequired(true))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                                RESET_PASSWORD_LINK_SENT),
                        new JourneyTransition(
                                userContext, USER_ENTERED_VALID_CREDENTIALS, CONSENT_REQUIRED));

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
    public void testCanReachForgottenPasswordAndUseBrowserBackToAttemptSignInWithMfa() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "1.0",
                        new HashSet<String>(
                                Arrays.asList(
                                        "phone",
                                        "phone_number_verified",
                                        "email",
                                        "email_verified",
                                        "sub")));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.MEDIUM_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl.Cm").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                                RESET_PASSWORD_LINK_SENT),
                        new JourneyTransition(
                                userContext, USER_ENTERED_VALID_CREDENTIALS, LOGGED_IN));

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
    public void testCanReachLockedAccountAndStartAgainAndCorrectlyGetBackToLockedStatus() {
        UserProfile userProfile =
                generateUserProfile(
                        true,
                        "1.0",
                        new HashSet<String>(
                                Arrays.asList(
                                        "phone",
                                        "phone_number_verified",
                                        "email",
                                        "email_verified",
                                        "sub")));

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.MEDIUM_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl.Cm").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .withUserProfile(userProfile)
                        .withClient(new ClientRegistry().setClientID(CLIENT_ID.toString()))
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                ACCOUNT_TEMPORARILY_LOCKED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                USER_NOT_FOUND),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                ACCOUNT_TEMPORARILY_LOCKED));

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
