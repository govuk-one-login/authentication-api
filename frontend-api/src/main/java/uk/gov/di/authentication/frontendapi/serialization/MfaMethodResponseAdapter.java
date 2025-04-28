package uk.gov.di.authentication.frontendapi.serialization;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import uk.gov.di.authentication.frontendapi.entity.mfa.AuthAppMfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.SmsMfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.io.IOException;

import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;

public class MfaMethodResponseAdapter extends TypeAdapter<MfaMethodResponse> {
    private final Gson gson = new Gson();

    @Override
    public void write(JsonWriter out, MfaMethodResponse value) throws IOException {
        gson.toJson(value, value.getClass(), out);
    }

    @Override
    public MfaMethodResponse read(JsonReader in) throws IOException {
        JsonObject jsonObject = JsonParser.parseReader(in).getAsJsonObject();
        String type = jsonObject.get("type").getAsString();
        MFAMethodType mfaMethodType = MFAMethodType.valueOf(type);
        return gson.fromJson(
                jsonObject,
                mfaMethodType == AUTH_APP
                        ? AuthAppMfaMethodResponse.class
                        : SmsMfaMethodResponse.class);
    }
}
