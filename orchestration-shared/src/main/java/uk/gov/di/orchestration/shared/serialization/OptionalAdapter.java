package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.Optional;

public class OptionalAdapter<E> extends TypeAdapter<Optional<E>> {

    public static final TypeAdapterFactory FACTORY =
            new TypeAdapterFactory() {
                @Override
                public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
                    Class<T> rawType = (Class<T>) type.getRawType();
                    if (rawType == Optional.class
                            && type.getType() instanceof ParameterizedType parameterizedType) {
                        return new OptionalAdapter(
                                gson.getAdapter(
                                        TypeToken.get(
                                                parameterizedType.getActualTypeArguments()[0])));
                    }
                    return null;
                }
            };

    private final TypeAdapter<E> valueAdapter;

    public OptionalAdapter(TypeAdapter<E> valueAdapter) {
        this.valueAdapter = valueAdapter;
    }

    @Override
    public Optional<E> read(JsonReader jsonReader) throws IOException {
        if (jsonReader.peek() != JsonToken.NULL) {
            return Optional.ofNullable(valueAdapter.read(jsonReader));
        } else {
            jsonReader.nextNull();
            return Optional.empty();
        }
    }

    @Override
    public void write(JsonWriter jsonWriter, Optional<E> value) throws IOException {
        if (value.isPresent()) {
            valueAdapter.write(jsonWriter, value.get());
        } else {
            jsonWriter.nullValue();
        }
    }
}
