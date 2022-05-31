package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.stream.MalformedJsonException;
import com.nimbusds.oauth2.sdk.id.State;

import java.io.IOException;

public class StateAdapter extends TypeAdapter<State> {
    @Override
    public void write(JsonWriter out, State value) throws IOException {
        out.value(value.getValue());
    }

    @Override
    public State read(JsonReader in) throws IOException {
        var token = in.peek();
        switch (token) {
            case BEGIN_ARRAY:
                in.beginArray();
                var state = in.nextString();
                in.endArray();
                return new State(state);
            case STRING:
                return new State(in.nextString());
            default:
                throw new MalformedJsonException(
                        "Expected BEGIN_ARRAY or STRING got " + token.name());
        }
    }
}
