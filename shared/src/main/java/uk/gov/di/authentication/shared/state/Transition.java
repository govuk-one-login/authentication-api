package uk.gov.di.authentication.shared.state;

public class Transition<T, A, C> {
    private final A action;
    private final T nextState;
    private final Condition<C> condition;

    public Transition(A action, T nextState, Condition<C> condition) {
        this.action = action;
        this.nextState = nextState;
        this.condition = condition;
    }

    public Transition(A action, T nextState) {
        this(action, nextState, new Default<C>());
    }

    public T getNextState() {
        return nextState;
    }

    public A getAction() {
        return action;
    }

    public Condition<C> getCondition() {
        return condition;
    }
}
