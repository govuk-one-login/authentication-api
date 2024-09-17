package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record AuthCodeRequest(
        @SerializedName("redirect-uri") @Expose @Required String redirectUri,
        @SerializedName("state") @Expose @Required String state,
        @SerializedName("claims") @Expose List<String> claims,
        @SerializedName("rp-sector-uri") @Expose @Required String sectorIdentifier,
        @SerializedName("is-new-account") @Expose @Required boolean isNewAccount,
        @SerializedName("password-reset-time") @Expose Long passwordResetTime) {}
