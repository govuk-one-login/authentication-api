package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.io.IOException;

public class ErrorResponseAdapter extends TypeAdapter<ErrorResponse> {
    @Override
    public void write(JsonWriter out, ErrorResponse value) throws IOException {
        out.beginObject();
        out.name("code").value(value.getCode());
        out.name("message").value(value.getMessage());
        out.endObject();
    }

    @Override
    public ErrorResponse read(JsonReader in) throws IOException {
        return null;
    }
}
