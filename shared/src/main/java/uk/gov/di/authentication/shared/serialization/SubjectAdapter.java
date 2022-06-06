package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.stream.MalformedJsonException;
import com.nimbusds.oauth2.sdk.id.Subject;

import java.io.IOException;
import java.util.Objects;

public class SubjectAdapter extends TypeAdapter<Subject> {
    @Override
    public void write(JsonWriter out, Subject value) throws IOException {
        if (Objects.nonNull(value)) {
            out.value(value.getValue());
        } else {
            out.nullValue();
        }
    }

    @Override
    public Subject read(JsonReader in) throws IOException {
        var token = in.peek();
        switch (token) {
            case STRING:
                return new Subject(in.nextString());
            case NULL:
                in.nextNull();
                return null;
            default:
                throw new MalformedJsonException("Expected NULL or STRING got " + token.name());
        }
    }
}
