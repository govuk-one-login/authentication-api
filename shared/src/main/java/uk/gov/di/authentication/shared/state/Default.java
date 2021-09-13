package uk.gov.di.authentication.shared.state;

public class Default<T> implements Condition<T> {
    @Override
    public boolean isMet(T context) {
        return true;
    }
}
