package uk.gov.di.authentication.sharedtest.matchers;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.mockito.ArgumentMatcher;

public class JsonArgumentMatcher implements ArgumentMatcher<String> {

    private final JsonObject expected;
    private final String[] fieldsToIgnore;
    private static final Gson gson = new Gson();

    private static JsonObject parseJson(String json) {
        return gson.fromJson(json, JsonObject.class);
    }

    private JsonObject removeFieldsFromJson(JsonObject json) {
        for (String fieldToIgnore : this.fieldsToIgnore) {
            json.remove(fieldToIgnore);
        }
        return json;
    }

    public JsonArgumentMatcher(String expected, String... fieldsToIgnore) {
        this.fieldsToIgnore = fieldsToIgnore;
        this.expected = removeFieldsFromJson(parseJson(expected));
    }

    @Override
    public boolean matches(String argument) {
        var actual = removeFieldsFromJson(parseJson(argument));

        return actual.equals(expected);
    }

    public static JsonArgumentMatcher partiallyContainsJsonString(
            String expected, String... fieldsToIgnore) {
        return new JsonArgumentMatcher(expected, fieldsToIgnore);
    }
}
