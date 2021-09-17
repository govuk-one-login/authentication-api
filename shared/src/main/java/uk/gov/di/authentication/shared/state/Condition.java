package uk.gov.di.authentication.shared.state;

import java.util.Optional;

public interface Condition<T> {
    boolean isMet(Optional<T> context);
}
