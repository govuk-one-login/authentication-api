package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nimbusds.oauth2.sdk.id.State;

import java.io.IOException;

public class StateAdapter extends TypeAdapter<State> {
    @Override
    public void write(JsonWriter out, State value) throws IOException {
        out.value(value.getValue());
    }

    @Override
    public State read(JsonReader in) throws IOException {
        return new State(in.nextString());
    }
}
