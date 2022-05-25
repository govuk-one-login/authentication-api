package uk.gov.di.authentication.sharedtest.matchers;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.mockito.ArgumentMatcher;

public class JsonArgumentMatcher implements ArgumentMatcher<String> {

    private final JsonElement expected;

    public JsonArgumentMatcher(String expected) {
        this.expected = JsonParser.parseString(expected);
    }

    @Override
    public boolean matches(String argument) {
        var actual = JsonParser.parseString(argument);
        return actual.equals(expected);
    }

    public static JsonArgumentMatcher containsJsonString(String expected) {
        return new JsonArgumentMatcher(expected);
    }
}
