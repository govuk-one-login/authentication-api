package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;

public record CheckReauthUserRequest(
        @SerializedName("email") @Expose @Required String email,
        @SerializedName("rpPairwiseId") @Expose @Required String rpPairwiseId) {}
