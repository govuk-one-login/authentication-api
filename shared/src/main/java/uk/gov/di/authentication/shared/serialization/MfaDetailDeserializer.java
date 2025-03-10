package uk.gov.di.authentication.shared.serialization;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import uk.gov.di.authentication.shared.entity.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.MfaDetail;
import uk.gov.di.authentication.shared.entity.SmsMfaDetail;

import java.lang.reflect.Type;

public class MfaDetailDeserializer implements JsonDeserializer<MfaDetail> {
    @Override
    public MfaDetail deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        String type = jsonObject.get("mfaMethodType").getAsString();

        if (MFAMethodType.SMS.getValue().equalsIgnoreCase(type)) {
            SmsMfaDetail smsDetail = context.deserialize(jsonObject, SmsMfaDetail.class);
            return new SmsMfaDetail(MFAMethodType.SMS, smsDetail.phoneNumber());
        } else if (MFAMethodType.AUTH_APP.getValue().equalsIgnoreCase(type)) {
            AuthAppMfaDetail authAppDetail =
                    context.deserialize(jsonObject, AuthAppMfaDetail.class);
            return new AuthAppMfaDetail(MFAMethodType.AUTH_APP, authAppDetail.credential());
        } else {
            throw new JsonParseException("Unknown mfa detail type: " + type);
        }
    }
}
