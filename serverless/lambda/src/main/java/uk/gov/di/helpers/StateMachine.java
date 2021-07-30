package uk.gov.di.helpers;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;

public class StateMachine<T> {

    private final Map<T, List<T>> states;

    public StateMachine(Map<T, List<T>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public boolean isValidTransition(T from, T to) {
        return states.getOrDefault(from, emptyList()).contains(to);
    }
}
