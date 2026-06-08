package uk.gov.di.authentication.frontendapi.entity.passkeys.audit;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;

public class PasskeyAllowedCredentialSerializer
        implements JsonSerializer<PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential> {

    @Override
    public JsonElement serialize(
            PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential src,
            Type typeOfSrc,
            JsonSerializationContext context) {
        var obj = new JsonObject();
        obj.addProperty("passkey_credential_id", src.passkeyCredentialId());
        if (src.passkeyCredentialTransports() != null
                && !src.passkeyCredentialTransports().isEmpty()) {
            obj.add(
                    "passkey_credential_transports",
                    context.serialize(src.passkeyCredentialTransports()));
        }
        return obj;
    }
}
