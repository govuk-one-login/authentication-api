package uk.gov.di.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.NEW;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.entity.SessionState.VERIFY_EMAIL_CODE_SENT;

public class StateMachine<T> {

    private final Map<T, List<T>> states;

    private static final Logger LOGGER = LoggerFactory.getLogger(StateMachine.class);

    public StateMachine(Map<T, List<T>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public boolean isValidTransition(T from, T to) {
        return states.getOrDefault(from, emptyList()).contains(to);
    }

    public static boolean isInvalidUserJourneyTransition(SessionState from, SessionState to) {
        return !userJourneyStateMachine().isValidTransition(from, to);
    }

    public static void validateStateTransition(Session session, SessionState to) {
        if (!userJourneyStateMachine().isValidTransition(session.getState(), to)) {
            LOGGER.info(
                    "Session attempted invalid transition from {} to {}", session.getState(), to);
            throw new InvalidStateTransitionException();
        }
    }

    public static StateMachine<SessionState> userJourneyStateMachine() {
        Map<SessionState, List<SessionState>> states =
                ofEntries(
                        entry(NEW, List.of(USER_NOT_FOUND)),
                        entry(
                                USER_NOT_FOUND,
                                List.of(AUTHENTICATION_REQUIRED, VERIFY_EMAIL_CODE_SENT)),
                        entry(
                                VERIFY_EMAIL_CODE_SENT,
                                List.of(EMAIL_CODE_VERIFIED, EMAIL_CODE_NOT_VALID)),
                        entry(
                                EMAIL_CODE_NOT_VALID,
                                List.of(
                                        EMAIL_CODE_VERIFIED,
                                        EMAIL_CODE_NOT_VALID,
                                        EMAIL_CODE_MAX_RETRIES_REACHED)),
                        entry(EMAIL_CODE_MAX_RETRIES_REACHED, Collections.emptyList()),
                        entry(
                                EMAIL_CODE_VERIFIED,
                                List.of(EMAIL_CODE_NOT_VALID, TWO_FACTOR_REQUIRED)));

        return new StateMachine<>(states);
    }

    public static class InvalidStateTransitionException extends RuntimeException {}
}
