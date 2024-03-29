package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record AccountInterventionState(
        @Expose boolean blocked,
        @Expose boolean suspended,
        @Expose @SerializedName("reproveIdentity") boolean reproveIdentity,
        @Expose @SerializedName("resetPassword") boolean resetPassword) {}
