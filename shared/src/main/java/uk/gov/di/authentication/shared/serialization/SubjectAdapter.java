package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.stream.MalformedJsonException;
import com.nimbusds.oauth2.sdk.id.Subject;

import java.io.IOException;

public class SubjectAdapter extends TypeAdapter<Subject> {
    @Override
    public void write(JsonWriter out, Subject value) throws IOException {
        out.value(value.getValue());
    }

    @Override
    public Subject read(JsonReader in) throws IOException {
        return new Subject(in.nextString());
    }
}
