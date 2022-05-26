package uk.gov.di.authentication.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.stream.MalformedJsonException;

import java.io.IOException;
import java.time.LocalDateTime;

public class LocalDateTimeAdapter extends TypeAdapter<LocalDateTime> {
    @Override
    public void write(JsonWriter out, LocalDateTime value) throws IOException {
        out.value(value.toString());
    }

    @Override
    public LocalDateTime read(JsonReader in) throws IOException {
        var token = in.peek();
        switch (token) {
            case BEGIN_ARRAY:
                in.beginArray();
                var year = in.nextInt();
                var month = in.nextInt();
                var day = in.nextInt();
                var hour = in.nextInt();
                var minute = in.nextInt();
                var seconds = in.nextInt();
                var nanos = in.nextInt();
                in.endArray();
                return LocalDateTime.of(year, month, day, hour, minute, seconds, nanos);
            case STRING:
                in.nextString();
                return LocalDateTime.parse(in.nextString());
            default:
                throw new MalformedJsonException(
                        "Expected BEGIN_ARRAY or STRING got " + token.name());
        }
    }
}
