package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record CheckReauthUserRequest(
        @SerializedName("email") @Expose @Required String email,
        @SerializedName("rpPairwiseId") @Expose @Required String rpPairwiseId) {}
