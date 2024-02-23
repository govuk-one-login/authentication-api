package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotComponent;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.HashMap;
import java.util.Map;

public class VotComponentAdapterFactory implements TypeAdapterFactory {

    private static final Map<Class, TypeAdapter> adapterLookup = new HashMap<>();

    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
        if (typeToken.getRawType().equals(VotComponent.class)
                && typeToken.getType() instanceof ParameterizedType type) {
            return adapterLookup.computeIfAbsent(
                    type.getActualTypeArguments()[0].getClass(),
                    enumClass ->
                            new TypeAdapter<T>() {

                                @Override
                                public void write(JsonWriter jsonWriter, T t) throws IOException {
                                    if (t == null) {
                                        jsonWriter.nullValue();
                                        return;
                                    }

                                    jsonWriter.value(t.toString());
                                }

                                @Override
                                public T read(JsonReader jsonReader) throws IOException {
                                    if (jsonReader.peek() == JsonToken.NULL) {
                                        jsonReader.nextNull();
                                        return null;
                                    }

                                    return (T)VotComponent.parse(enumClass, jsonReader.nextString());
                                }
                            });
        }

        // Returning null communicates to gson that this factory does not support the given type.
        return null;
    }
}
