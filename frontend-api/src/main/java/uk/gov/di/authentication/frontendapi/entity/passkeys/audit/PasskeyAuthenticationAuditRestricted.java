package uk.gov.di.authentication.frontendapi.entity.passkeys.audit;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public record PasskeyAuthenticationAuditRestricted(
        @SerializedName("passkey_allowed_credentials") @Expose
                List<PasskeyAllowedCredential> passkeyAllowedCredentials) {
    public record PasskeyAllowedCredential(
            @SerializedName("passkey_credential_id") @Expose String passkeyCredentialId,
            @SerializedName("passkey_credential_transports") @Expose
                    List<String> passkeyCredentialTransports) {}
}
