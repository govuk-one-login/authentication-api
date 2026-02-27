package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record PasskeysCreateRequest(
        @SerializedName("credential") @Expose @Required String credential,
        @SerializedName("id") @Expose @Required String passkeyId,
        @SerializedName("aaguid") @Expose @Required String aaguid,
        @SerializedName("isAttested") @Expose @Required boolean isAttested,
        @SerializedName("signCount") @Expose @Required int signCount,
        @SerializedName("transports") @Expose @Required List<String> transports,
        @SerializedName("isBackUpEligible") @Expose @Required boolean isBackUpEligible,
        @SerializedName("isBackedUp") @Expose @Required boolean isBackedUp,
        @SerializedName("isResidentKey") @Expose @Required boolean isResidentKey) {}
