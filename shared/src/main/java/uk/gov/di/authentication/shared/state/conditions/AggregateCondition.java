package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.state.Condition;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class AggregateCondition<T> implements Condition<T> {

    private final List<Condition<T>> conditions;

    public AggregateCondition(Condition<T>... conditions) {
        this.conditions = Arrays.asList(conditions);
    }

    @Override
    public boolean isMet(Optional<T> context) {
        return conditions.stream().allMatch(c -> c.isMet(context));
    }

    @SafeVarargs
    public static <T> AggregateCondition<T> and(Condition<T>... conditions) {
        return new AggregateCondition<>(conditions);
    }
}
