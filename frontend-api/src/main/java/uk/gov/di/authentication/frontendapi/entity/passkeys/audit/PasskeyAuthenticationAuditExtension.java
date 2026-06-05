package uk.gov.di.authentication.frontendapi.entity.passkeys.audit;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record PasskeyAuthenticationAuditExtension(
        @Expose @SerializedName("passkey_authentication_request")
                PasskeyAuthenticationRequest passkeyAuthenticationRequest) {
    public record PasskeyAuthenticationRequest(
            @Expose @SerializedName("passkey_request_user_verification")
                    String passkeyRequestUserVerification) {}

    public static PasskeyAuthenticationAuditExtension fromUserVerification(
            String userVerification) {
        return new PasskeyAuthenticationAuditExtension(
                new PasskeyAuthenticationRequest(userVerification));
    }
}
