package uk.gov.di.authentication.shared.state;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_A_NEW_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_CREATED_A_PASSWORD;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_PHONE_NUMBER_CODE_SENT;

public class StateMachine<T, A, C> {

    private final Map<T, List<Transition<T, A, C>>> states;

    private static final Logger LOGGER = LoggerFactory.getLogger(StateMachine.class);

    public StateMachine(Map<T, List<Transition<T, A, C>>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public T transition(T from, A action, Optional<C> context) {
            T to =
                    states.getOrDefault(from, emptyList()).stream()
                            .filter(t -> t.getAction().equals(action))
                            .findFirst()
                            .orElseThrow(() -> handleBadStateTransition(from, action))
                            .getNextState();

            LOGGER.info("Session transitioned from {} to {} on action {}", from, to, action);

            return to;
    }

    public T transition(T from, A action) {
        return transition(from, action, Optional.empty());
    }

    public static StateMachine<SessionState, SessionAction, UserProfile> userJourneyStateMachine() {
        Map<SessionState, List<Transition<SessionState, SessionAction, UserProfile>>> states =
                ofEntries(
                        entry(
                                NEW,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                                USER_NOT_FOUND))),
                        entry(
                                USER_NOT_FOUND,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                                USER_NOT_FOUND),
                                        new Transition<>(
                                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                                AUTHENTICATION_REQUIRED),
                                        new Transition<>(
                                                SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE,
                                                VERIFY_EMAIL_CODE_SENT))),
                        entry(
                                VERIFY_EMAIL_CODE_SENT,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE,
                                                EMAIL_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                                EMAIL_CODE_NOT_VALID))),
                        entry(
                                EMAIL_CODE_NOT_VALID,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE,
                                                EMAIL_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                                EMAIL_CODE_NOT_VALID),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                                                EMAIL_CODE_MAX_RETRIES_REACHED))),
                        entry(EMAIL_CODE_MAX_RETRIES_REACHED, Collections.emptyList()),
                        entry(
                                EMAIL_CODE_VERIFIED,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                                                EMAIL_CODE_NOT_VALID),
                                        new Transition<>(
                                                USER_HAS_CREATED_A_PASSWORD, TWO_FACTOR_REQUIRED))),
                        entry(
                                TWO_FACTOR_REQUIRED,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_A_NEW_PHONE_NUMBER,
                                                ADDED_UNVERIFIED_PHONE_NUMBER))),
                        entry(
                                ADDED_UNVERIFIED_PHONE_NUMBER,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE,
                                                VERIFY_PHONE_NUMBER_CODE_SENT))),
                        entry(
                                VERIFY_PHONE_NUMBER_CODE_SENT,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_VALID_PHONE_VERIFICATION_CODE,
                                                PHONE_NUMBER_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE,
                                                PHONE_NUMBER_CODE_NOT_VALID))),
                        entry(
                                PHONE_NUMBER_CODE_VERIFIED,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE,
                                                AUTHENTICATED))),
                        entry(
                                PHONE_NUMBER_CODE_NOT_VALID,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_VALID_PHONE_VERIFICATION_CODE,
                                                PHONE_NUMBER_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE,
                                                PHONE_NUMBER_CODE_NOT_VALID),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES,
                                                PHONE_NUMBER_CODE_MAX_RETRIES_REACHED))),
                        entry(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED, Collections.emptyList()),
                        entry(
                                AUTHENTICATION_REQUIRED,
                                List.of(
                                        new Transition<>(USER_ENTERED_VALID_CREDENTIALS, LOGGED_IN),
                                        new Transition<>(
                                                USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                                USER_NOT_FOUND))),
                        entry(
                                LOGGED_IN,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_SENT_MFA_CODE, MFA_SMS_CODE_SENT))),
                        entry(
                                MFA_SMS_CODE_SENT,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_SENT_MFA_CODE, MFA_SMS_CODE_SENT),
                                        new Transition<>(
                                                USER_ENTERED_VALID_MFA_CODE, MFA_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_MFA_CODE,
                                                MFA_CODE_NOT_VALID))),
                        entry(
                                MFA_CODE_NOT_VALID,
                                List.of(
                                        new Transition<>(
                                                USER_ENTERED_VALID_MFA_CODE, MFA_CODE_VERIFIED),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_MFA_CODE, MFA_CODE_NOT_VALID),
                                        new Transition<>(
                                                USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES,
                                                MFA_CODE_MAX_RETRIES_REACHED))),
                        entry(MFA_CODE_MAX_RETRIES_REACHED, Collections.emptyList()),
                        entry(
                                MFA_CODE_VERIFIED,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE,
                                                AUTHENTICATED))),
                        entry(
                                AUTHENTICATED,
                                List.of(
                                        new Transition<>(
                                                SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE,
                                                AUTHENTICATED))));

        return new StateMachine<>(states);
    }

    public static class InvalidStateTransitionException extends RuntimeException {}

    private InvalidStateTransitionException handleBadStateTransition(T from, A action) {
        LOGGER.error("Session attempted invalid transition from {} on action {}", from, action);
        return new InvalidStateTransitionException();
    }
}
