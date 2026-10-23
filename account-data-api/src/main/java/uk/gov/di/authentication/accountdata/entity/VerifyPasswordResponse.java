package uk.gov.di.authentication.accountdata.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record VerifyPasswordResponse(
        @SerializedName("verified") @Expose @Required boolean verified) {}
