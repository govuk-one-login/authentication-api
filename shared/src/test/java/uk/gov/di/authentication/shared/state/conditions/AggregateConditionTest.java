package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.state.Condition;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class AggregateConditionTest {

    private static final Condition<Object> TRUE_CONDITION = context -> true;

    private static final Condition<Object> FALSE_CONDITION = context -> false;


    @Test
    public void shouldReturnTrueIfAllConditionsAreTrue() {
        AggregateCondition<Object> condition = new AggregateCondition<>(
                TRUE_CONDITION,
                TRUE_CONDITION,
                TRUE_CONDITION
        );

        assertThat(condition.isMet(Optional.empty()), equalTo(true));
    }

    @Test
    public void shouldReturnFalseIfAnyConditionIsFalse() {
        AggregateCondition<Object> condition = new AggregateCondition<>(
                TRUE_CONDITION,
                FALSE_CONDITION,
                TRUE_CONDITION
        );

        assertThat(condition.isMet(Optional.empty()), equalTo(false));
    }
}