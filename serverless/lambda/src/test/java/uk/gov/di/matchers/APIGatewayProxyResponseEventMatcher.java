package uk.gov.di.matchers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.function.Function;

public class APIGatewayProxyResponseEventMatcher<T>
        extends TypeSafeDiagnosingMatcher<APIGatewayProxyResponseEvent> {

    private final String name;
    private final Function<APIGatewayProxyResponseEvent, T> mapper;
    private final T expected;

    private APIGatewayProxyResponseEventMatcher(
            String name, Function<APIGatewayProxyResponseEvent, T> mapper, T expected) {
        this.name = name;
        this.mapper = mapper;
        this.expected = expected;
    }

    @Override
    protected boolean matchesSafely(
            APIGatewayProxyResponseEvent item, Description mismatchDescription) {
        boolean matched = mapper.apply(item).equals(expected);

        if (!matched) {
            mismatchDescription.appendText(description());
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(description());
    }

    private String description() {
        return "an APIGatewayProxyResponseEvent with " + name + ": " + expected;
    }

    public static APIGatewayProxyResponseEventMatcher<Integer> hasStatus(int statusCode) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "status code", APIGatewayProxyResponseEvent::getStatusCode, statusCode);
    }
}
