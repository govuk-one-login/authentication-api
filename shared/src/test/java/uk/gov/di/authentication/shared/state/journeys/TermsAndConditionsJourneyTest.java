package uk.gov.di.authentication.shared.state.journeys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateAuthRequest;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateLowLevelVectorOfTrust;
import static uk.gov.di.authentication.shared.state.StateMachineJourneyTest.generateUserProfile;

public class TermsAndConditionsJourneyTest {
    private final ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

    private final Session session = new Session(IdGenerator.generate());

    private StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getTermsAndConditionsVersion()).thenReturn("1.0");

        stateMachine = StateMachine.userJourneyStateMachine(mockConfigurationService);
    }

    @Test
    public void testCanReachTermsAndConditionsWithout2FA() {
        UserProfile userProfile = generateUserProfile(true, "0.1");

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
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
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
    public void testCanReachTermsAndConditionsWith2FA() {
        UserProfile userProfile = generateUserProfile(true, "0.1");

        UserContext userContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.MEDIUM_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl.Cm").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(generateLowLevelVectorOfTrust()))
                        .withUserProfile(userProfile)
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext, USER_ENTERED_VALID_CREDENTIALS, LOGGED_IN),
                        new JourneyTransition(
                                userContext, SYSTEM_HAS_SENT_MFA_CODE, MFA_SMS_CODE_SENT),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_VALID_MFA_CODE,
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
    public void
            testAfterReachingTermsAndConditionsNewSessionShouldGoBackToTermsAndConditionsIfUpliftIsNotRequired() {
        UserProfile userProfile = generateUserProfile(true, "0.1");

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
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_VALID_CREDENTIALS,
                                UPDATED_TERMS_AND_CONDITIONS),
                        new JourneyTransition(
                                userContext,
                                USER_HAS_STARTED_A_NEW_JOURNEY,
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
    public void
            testNewSessionAfterReachingTermsAndConditionsShouldGoTo_MFA_SMS_CODE_SENT_WhenUpliftIsRequired() {
        UserProfile userProfile = generateUserProfile(true, "0.1");

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
                        .build();

        UserContext upliftedUserContext =
                UserContext.builder(
                                session.setCurrentCredentialStrength(
                                        CredentialTrustLevel.LOW_LEVEL))
                        .withClientSession(
                                new ClientSession(
                                                generateAuthRequest("Cl").toParameters(),
                                                null,
                                                null)
                                        .setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()))
                        .withUserProfile(userProfile)
                        .build();

        List<JourneyTransition> transitions =
                Arrays.asList(
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                AUTHENTICATION_REQUIRED),
                        new JourneyTransition(
                                userContext,
                                USER_ENTERED_VALID_CREDENTIALS,
                                UPDATED_TERMS_AND_CONDITIONS),
                        new JourneyTransition(
                                upliftedUserContext,
                                USER_HAS_STARTED_A_NEW_JOURNEY,
                                UPLIFT_REQUIRED_CM),
                        new JourneyTransition(
                                upliftedUserContext, SYSTEM_HAS_SENT_MFA_CODE, MFA_SMS_CODE_SENT));

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
