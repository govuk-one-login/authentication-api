package uk.gov.di.authentication.shared.state;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
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
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class StateMachineJourneyTest {

    public static final ClientID CLIENT_ID = new ClientID("test-client");

    private static final URI REDIRECT_URI = URI.create("test-uri");

    private final ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

    private final Session session = new Session(IdGenerator.generate());

    private StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(StateMachine.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID.toString(), session.getSessionId()))));
    }

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getTermsAndConditionsVersion()).thenReturn("1.0");

        stateMachine = StateMachine.userJourneyStateMachine(mockConfigurationService);
    }

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

    public static UserProfile generateUserProfile(
            boolean phoneNumberVerified,
            String acceptedTermsAndConditionsVersion,
            Set<String> consentClaims) {
        UserProfile userProfile = new UserProfile();
        userProfile.setPhoneNumberVerified(phoneNumberVerified);
        userProfile.setTermsAndConditions(
                new TermsAndConditions(acceptedTermsAndConditionsVersion, new Date().toString()));
        userProfile.setClientConsent(
                new ClientConsent(CLIENT_ID.toString(), consentClaims, new Date().toString()));
        return userProfile;
    }

    public static VectorOfTrust generateLowLevelVectorOfTrust() {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                Collections.singletonList(jsonArrayOf("Cl")));
    }

    public static AuthenticationRequest generateAuthRequest(String vtr) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .customParameter("vtr", jsonArrayOf(vtr))
                .build();
    }
}
