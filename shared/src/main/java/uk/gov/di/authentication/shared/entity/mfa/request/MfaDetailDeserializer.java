package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;

import java.lang.reflect.Type;

public class MfaDetailDeserializer implements JsonDeserializer<MfaDetail> {
    @Override
    public MfaDetail deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        JsonElement typeAsJsonElement = jsonObject.get("mfaMethodType");

        if (typeAsJsonElement == null) {
            throw new JsonParseException("MFA method type is missing");
        }

        var type = typeAsJsonElement.getAsString();

        if (MFAMethodType.SMS.getValue().equalsIgnoreCase(type)) {
            JsonElement phoneNumberAsJson = jsonObject.get("phoneNumber");

            if (phoneNumberAsJson == null) {
                throw new JsonParseException("Phone number is missing");
            }

            var phoneNumber = phoneNumberAsJson.getAsString();

            JsonElement otpAsJson = jsonObject.get("otp");

            if (otpAsJson == null) {
                throw new JsonParseException("OTP is missing");
            }

            var otp = otpAsJson.getAsString();

            return new RequestSmsMfaDetail(phoneNumber, otp);
        } else if (MFAMethodType.AUTH_APP.getValue().equalsIgnoreCase(type)) {
            JsonElement credentialAsJson = jsonObject.get("credential");

            if (credentialAsJson == null) {
                throw new JsonParseException("Credential is missing");
            }

            var credential = credentialAsJson.getAsString();

            return new RequestAuthAppMfaDetail(credential);
        } else {
            throw new JsonParseException("Unknown mfa detail type: " + type);
        }
    }
}
