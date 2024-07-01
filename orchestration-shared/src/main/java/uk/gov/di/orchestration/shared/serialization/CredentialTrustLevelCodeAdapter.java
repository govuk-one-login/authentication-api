package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevelCode;

import java.io.IOException;
import java.util.Objects;

public class CredentialTrustLevelCodeAdapter extends TypeAdapter<CredentialTrustLevelCode> {
    @Override
    public void write(JsonWriter jsonWriter, CredentialTrustLevelCode code) throws IOException {
        if (Objects.isNull(code)) {
            jsonWriter.nullValue();
            return;
        }

        jsonWriter.value(code.toString());
    }

    @Override
    public CredentialTrustLevelCode read(JsonReader jsonReader) throws IOException {
        if (jsonReader.peek() == JsonToken.NULL) {
            jsonReader.nextNull();
            return null;
        }

        return CredentialTrustLevelCode.parse(jsonReader.nextString());
    }
}
