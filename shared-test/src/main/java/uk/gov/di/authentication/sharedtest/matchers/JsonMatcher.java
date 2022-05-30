package uk.gov.di.authentication.sharedtest.matchers;

import com.google.gson.JsonElement;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.function.Function;

import static java.lang.String.format;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class JsonMatcher<T> extends TypeSafeDiagnosingMatcher<JsonElement> {

    private final String name;
    private final Function<JsonElement, T> mapper;
    private final Matcher<T> matcher;

    private JsonMatcher(String name, Function<JsonElement, T> mapper, Matcher<T> matcher) {
        this.name = name;
        this.mapper = mapper;
        this.matcher = matcher;
    }

    @Override
    protected boolean matchesSafely(JsonElement item, Description mismatchDescription) {
        T actual = mapper.apply(item);

        boolean matched = matcher.matches(actual);

        if (!matched) {
            mismatchDescription.appendText(description(actual, item.toString()));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendDescriptionOf(matcher);
    }

    private String description(T value, String actualJson) {
        return format("a Json object with %s: %s (%s)", name, value, actualJson);
    }

    public static JsonMatcher<JsonElement> hasField(final String fieldName) {
        return new JsonMatcher<>(
                fieldName,
                node -> node.getAsJsonObject().get(fieldName),
                is(notNullValue(JsonElement.class)));
    }

    public static JsonMatcher<String> hasFieldWithValue(
            final String fieldName, Matcher<String> expected) {
        return new JsonMatcher<>(
                fieldName,
                node ->
                        node.getAsJsonObject().get(fieldName) == null
                                ? null
                                : node.getAsJsonObject().get(fieldName).getAsString(),
                expected);
    }
}
