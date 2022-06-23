package uk.gov.di.authentication.sharedtest.matchers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.URI;
import java.util.function.Function;

import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

public class APIGatewayProxyResponseEventMatcher<T>
        extends TypeSafeDiagnosingMatcher<APIGatewayProxyResponseEvent> {

    private final String name;
    private final Function<APIGatewayProxyResponseEvent, T> mapper;
    private final Matcher<T> matcher;

    private APIGatewayProxyResponseEventMatcher(
            String name, Function<APIGatewayProxyResponseEvent, T> mapper, Matcher<T> matcher) {
        this.name = name;
        this.mapper = mapper;
        this.matcher = matcher;
    }

    @Override
    protected boolean matchesSafely(
            APIGatewayProxyResponseEvent item, Description mismatchDescription) {
        var actual = mapper.apply(item);

        boolean matched = matcher.matches(actual);

        if (!matched) {
            mismatchDescription.appendText(description(actual));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendDescriptionOf(matcher);
    }

    private String description(T value) {
        return "an APIGatewayProxyResponseEvent with " + name + ": " + value;
    }

    public static APIGatewayProxyResponseEventMatcher<Integer> hasStatus(
            int statusCode) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "status code", APIGatewayProxyResponseEvent::getStatusCode, equalTo(statusCode));
    }

    public static APIGatewayProxyResponseEventMatcher<Integer> hasStatus(
            Matcher<Integer> statusCodeMatcher) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "status code", APIGatewayProxyResponseEvent::getStatusCode, statusCodeMatcher);
    }

    public static APIGatewayProxyResponseEventMatcher<String> hasBody(
            String body) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "body", APIGatewayProxyResponseEvent::getBody, equalTo(body));
    }

    public static APIGatewayProxyResponseEventMatcher<String> hasJsonBody(
            Object body) {
        var expectedValue =
                unchecked(SerializationService.getInstance()::writeValueAsString).apply(body);

        return new APIGatewayProxyResponseEventMatcher<>(
                "body", APIGatewayProxyResponseEvent::getBody, equalTo(expectedValue));
    }

    public static APIGatewayProxyResponseEventMatcher<Integer> isRedirect() {
        return hasStatus(302);
    }

    public static APIGatewayProxyResponseEventMatcher<URI> isRedirectTo(
            Matcher<URI> expected) {
        return new APIGatewayProxyResponseEventMatcher<>(
                "redirect to",
                apiGatewayProxyResponseEvent ->
                        URI.create(apiGatewayProxyResponseEvent.getHeaders().get("Location")),
                expected);
    }
}
