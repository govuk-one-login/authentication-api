package uk.gov.di.authentication.accountdata.entity.passkey;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record PasskeysUpdateRequest(
        @SerializedName("signCount") @Expose @Required Integer signCount,
        @SerializedName("lastUsedAt") @Expose @Required String lastUsedAt) {}
