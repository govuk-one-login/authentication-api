package uk.gov.di.authentication.shared.serialization;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;

import java.lang.reflect.Type;

public class MfaDetailDeserializer implements JsonDeserializer<MfaDetail> {
    @Override
    public MfaDetail deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        String type = jsonObject.get("mfaMethodType").getAsString();

        if (MFAMethodType.SMS.getValue().equalsIgnoreCase(type)) {
            String phoneNumber = jsonObject.get("phoneNumber").getAsString();
            return new SmsMfaDetail(phoneNumber);
        } else if (MFAMethodType.AUTH_APP.getValue().equalsIgnoreCase(type)) {
            String credential = jsonObject.get("credential").getAsString();
            return new AuthAppMfaDetail(credential);
        } else {
            throw new JsonParseException("Unknown mfa detail type: " + type);
        }
    }
}
