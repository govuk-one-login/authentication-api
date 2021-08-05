package uk.gov.di.helpers;

import uk.gov.di.entity.SessionState;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.NEW;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.entity.SessionState.VERIFY_EMAIL_CODE_SENT;

public class StateMachine<T> {

    private final Map<T, List<T>> states;

    public StateMachine(Map<T, List<T>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public boolean isValidTransition(T from, T to) {
        return states.getOrDefault(from, emptyList()).contains(to);
    }

    public static boolean isInvalidUserJourneyTransition(SessionState from, SessionState to) {
        return !userJourneyStateMachine().isValidTransition(from, to);
    }

    public static StateMachine<SessionState> userJourneyStateMachine() {
        Map<SessionState, List<SessionState>> states =
                ofEntries(
                        entry(NEW, List.of(USER_NOT_FOUND)),
                        entry(
                                USER_NOT_FOUND,
                                List.of(AUTHENTICATION_REQUIRED, VERIFY_EMAIL_CODE_SENT)),
                        entry(EMAIL_CODE_VERIFIED, List.of(TWO_FACTOR_REQUIRED)));

        return new StateMachine<>(states);
    }
}
