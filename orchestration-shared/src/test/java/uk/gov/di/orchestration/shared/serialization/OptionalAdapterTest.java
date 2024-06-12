package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class OptionalAdapterTest {

    private static final Type OPTIONAL_OF_STRING_TYPE =
            new TypeToken<Optional<String>>() {}.getType();

    public Gson gson;

    @BeforeEach
    void setup() {
        gson = new GsonBuilder().registerTypeAdapterFactory(OptionalAdapter.FACTORY).create();
    }

    @Test
    void shouldSerializeEmptyOptionalAsNull() {
        var optional = Optional.empty();
        var actualJson = gson.toJson(optional, OPTIONAL_OF_STRING_TYPE);
        assertThat(actualJson, is(equalTo("null")));
    }

    @Test
    void shouldSerializeNonEmptyOptionalAsValue() {
        var optional = Optional.of("some text");
        var json = gson.toJson(optional, OPTIONAL_OF_STRING_TYPE);
        assertThat(json, is(equalTo("\"some text\"")));
    }

    @Test
    void shouldDeserializeNullAsEmptyOptional() {
        var json = "null";
        var optional = gson.fromJson(json, OPTIONAL_OF_STRING_TYPE);
        assertThat(optional, is(equalTo(Optional.empty())));
    }

    @Test
    void shouldDeserializeValuesAsNonEmptyOptional() {
        var json = "\"some text\"";
        var optional = gson.fromJson(json, OPTIONAL_OF_STRING_TYPE);
        assertThat(optional, is(equalTo(Optional.of("some text"))));
    }
}
