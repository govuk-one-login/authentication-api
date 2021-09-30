package uk.gov.di.authentication.sharedtest.matchers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
        var actual = mapper.apply(item);

        boolean matched = actual.equals(expected);

        if (!matched) {
            mismatchDescription.appendText(description(actual));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(description(expected));
    }

    private String description(T value) {
        return "an APIGatewayProxyResponseEvent with " + name + ": " + value;
    }

    public static APIGatewayProxyResponseEventMatcher<Integer> hasStatus(int statusCode) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "status code", APIGatewayProxyResponseEvent::getStatusCode, statusCode);
    }

    public static APIGatewayProxyResponseEventMatcher<String> hasBody(String body) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "body", APIGatewayProxyResponseEvent::getBody, body);
    }

    public static APIGatewayProxyResponseEventMatcher<String> hasJsonBody(Object body) {
        try {
            var expectedValue = new ObjectMapper().writeValueAsString(body);
            return new APIGatewayProxyResponseEventMatcher<>(
                    "body", APIGatewayProxyResponseEvent::getBody, expectedValue);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
