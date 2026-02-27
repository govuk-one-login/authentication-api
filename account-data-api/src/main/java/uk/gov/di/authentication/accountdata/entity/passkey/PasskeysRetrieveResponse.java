package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record PasskeysRetrieveResponse(
        @SerializedName("passkeys") @Expose @Required List<PasskeyResponse> passkeys) {

    public record PasskeyResponse(
            @SerializedName("id") @Expose @Required String passkeyId,
            @SerializedName("credential") @Expose @Required String credential,
            @SerializedName("aaguid") @Expose @Required String aaguid,
            @SerializedName("isAttested") @Expose @Required boolean isAttested,
            @SerializedName("signCount") @Expose @Required int signCount,
            @SerializedName("transports") @Expose @Required List<String> transports,
            @SerializedName("isBackUpEligible") @Expose @Required boolean isBackUpEligible,
            @SerializedName("isBackedUp") @Expose @Required boolean isBackedUp,
            @SerializedName("createdAt") @Expose String createdAt,
            @SerializedName("lastUsedAt") @Expose String lastUsedAt) {}

    public static Result<Void, PasskeyResponse> from(Passkey passkey) {
        return Result.success(
                new PasskeyResponse(
                        passkey.getCredentialId(),
                        passkey.getCredential(),
                        passkey.getPasskeyAaguid(),
                        passkey.getPasskeyIsAttested(),
                        passkey.getPasskeySignCount(),
                        passkey.getPasskeyTransports(),
                        passkey.getPasskeyBackupEligible(),
                        passkey.getPasskeyBackedUp(),
                        passkey.getCreated(),
                        passkey.getLastUsed()));
    }
}
