package uk.gov.di.authentication.shared.state;

public interface Condition<T> {
    boolean isMet(T context);
}
