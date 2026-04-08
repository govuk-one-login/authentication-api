package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class RSAKeyAdapter extends TypeAdapter<RSAKey> {

    @Override
    public void write(JsonWriter out, RSAKey value) throws IOException {
        if (value == null) {
            out.nullValue();
            return;
        }

        String jsonString = value.toJSONObject().toString();
        JsonElement jsonElement = JsonParser.parseString(jsonString);
        Streams.write(jsonElement, out);
    }

    @Override
    public RSAKey read(JsonReader in) throws IOException {
        JsonElement jsonElement = Streams.parse(in);

        if (jsonElement.isJsonNull()) {
            return null;
        }

        try {
            return RSAKey.parse(jsonElement.toString());
        } catch (ParseException e) {
            throw new IOException("Failed to parse JWK RSAKey: " + e.getMessage(), e);
        }
    }
}
