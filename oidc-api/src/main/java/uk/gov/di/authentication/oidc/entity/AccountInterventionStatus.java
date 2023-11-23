package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record AccountInterventionStatus(
        @Expose boolean blocked,
        @Expose boolean suspended,
        @Expose @SerializedName("reproveIdentity") boolean reproveIdentity,
        @Expose @SerializedName("resetPassword") boolean resetPassword) {}
