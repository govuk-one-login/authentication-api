package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record PasskeysCreateRequest(
        @SerializedName("id") @Expose @Required String passkeyId,
        @Expose @Required String credential,
        @Expose @Required String aaguid,
        @Expose @Required boolean isAttested,
        @Expose @Required int signCount,
        @Expose @Required List<String> transports,
        @Expose @Required boolean isBackUpEligible,
        @Expose @Required boolean isBackedUp,
        @Expose @Required boolean isResidentKey,
        @Expose @Required int algorithm) {}
