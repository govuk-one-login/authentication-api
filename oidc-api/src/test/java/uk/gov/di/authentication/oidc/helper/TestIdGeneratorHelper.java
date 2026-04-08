package uk.gov.di.authentication.oidc.helper;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;

import java.util.List;
import java.util.function.Supplier;

import static java.lang.String.format;
import static org.mockito.AdditionalAnswers.returnsElementsOf;
import static org.mockito.Mockito.mockStatic;

public class TestIdGeneratorHelper {
    /**
     * This test helper runs some code while static mocking the IdGenerator. When provided with a
     * list of IDs, it will iterate through the list and return the element for each
     * IdGenerator.generate() call.
     *
     * <p>For examples, check out the test for this helper class: {@link TestIdGeneratorHelperTest}
     *
     * @param method The code that uses IdGenerator.generate() you want to run
     * @param ids The ordered list of ids you want the generator to return
     * @param <T> The return type of the method
     * @return The result of calling the method
     */
    public static <T> T runWithIds(Supplier<T> method, List<String> ids) {
        try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
            mockIdGenerator.when(IdGenerator::generate).then(returnsElementsOf(ids));
            return method.get();
        }
    }

    public static <T> T runWithIncrementalIds(Supplier<T> method, String idPrefix) {
        var incrementalIdGenerator = new IncrementalIdGenerator(idPrefix);
        try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
            mockIdGenerator.when(IdGenerator::generate).then(incrementalIdGenerator);
            return method.get();
        }
    }

    private static class IncrementalIdGenerator implements Answer<String> {
        private final String prefix;
        private int idNum = 1;

        IncrementalIdGenerator(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public String answer(InvocationOnMock invocation) {
            return format("%s%d", prefix, idNum++);
        }
    }
}
