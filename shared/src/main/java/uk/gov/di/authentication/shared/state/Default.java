package uk.gov.di.authentication.shared.state;

import java.util.Optional;

public class Default<T> implements Condition<T> {
    @Override
    public boolean isMet(Optional<T> context) {
        return true;
    }
}
