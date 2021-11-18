package uk.gov.di.authentication.sharedtest.matchers;

import com.fasterxml.jackson.databind.JsonNode;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.function.Function;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class JsonMatcher<T> extends TypeSafeDiagnosingMatcher<JsonNode> {

    private final String name;
    private final Function<JsonNode, T> mapper;
    private final Matcher<T> matcher;

    private JsonMatcher(String name, Function<JsonNode, T> mapper, Matcher<T> matcher) {
        this.name = name;
        this.mapper = mapper;
        this.matcher = matcher;
    }

    @Override
    protected boolean matchesSafely(JsonNode item, Description mismatchDescription) {
        T actual = mapper.apply(item);

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
        return "a Json object with " + name + ": " + value;
    }

    public static JsonMatcher<JsonNode> hasField(final String fieldName) {
        return new JsonMatcher<>(
                fieldName, node -> node.get(fieldName), is(notNullValue(JsonNode.class)));
    }

    public static JsonMatcher<String> hasFieldWithValue(
            final String fieldName, Matcher<String> expected) {
        return new JsonMatcher<>(
                fieldName,
                node -> node.get(fieldName) == null ? null : node.get(fieldName).asText(),
                expected);
    }
}
