package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record AccountInterventionDetails(
        @Expose @SerializedName("updatedAt") Long updatedAt,
        @Expose @SerializedName("appliedAt") Long appliedAt,
        @Expose @SerializedName("sentAt") Long sentAt,
        @Expose @SerializedName("description") String description,
        @Expose @SerializedName("reprovedIdentityAt") Long reprovedIdentityAt,
        @Expose @SerializedName("resetPasswordAt") Long resetPasswordAt) {}
