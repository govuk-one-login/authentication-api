package uk.gov.di.helpers;

import uk.gov.di.entity.SessionState;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.entity.SessionState.USER_NOT_FOUND;

public class StateMachine<T> {

    private final Map<T, List<T>> states;

    public StateMachine(Map<T, List<T>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public boolean isValidTransition(T from, T to) {
        return states.getOrDefault(from, emptyList()).contains(to);
    }

    public static StateMachine<SessionState> userJourneyStateMachine() {
        var states =
                ofEntries(
                        entry(USER_NOT_FOUND, List.of(TWO_FACTOR_REQUIRED)),
                        entry(AUTHENTICATION_REQUIRED, List.of(TWO_FACTOR_REQUIRED)));

        return new StateMachine<>(states);
    }
}
