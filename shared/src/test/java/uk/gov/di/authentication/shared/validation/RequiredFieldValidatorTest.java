package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;

class RequiredFieldValidatorTest {

    private RequiredFieldValidator validator = new RequiredFieldValidator();

    @Test
    void shouldReturnNoErrorsWhenAllFieldsPassValidation() {
        var subject = new TestClass("value1", 2, null);

        assertThat(validator.validate(subject), hasSize(0));
    }

    @ParameterizedTest
    @MethodSource("failScenarios")
    void shouldReturnCorrectViolationWhenFieldsFailValidation(
            TestClass subject, String[] violations) {
        assertThat(validator.validate(subject), containsInAnyOrder(violations));
    }

    public static Stream<Arguments> failScenarios() {
        return Stream.of(
                Arguments.of(new TestClass(null, 2, "3"), new String[] {"field1"}),
                Arguments.of(new TestClass(null, null, "3"), new String[] {"field1", "field2"}),
                Arguments.of(new TestClass("value1", null, "3"), new String[] {"field2"}));
    }

    private static class TestClass {

        @Required private final String field1;

        @Required private final Integer field2;

        private final String field3;

        private TestClass(String field1, Integer field2, String field3) {
            this.field1 = field1;
            this.field2 = field2;
            this.field3 = field3;
        }
    }
}
