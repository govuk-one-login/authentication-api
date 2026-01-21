package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record CheckReauthUserRequest(
        @SerializedName("email") @Expose String email,
        @SerializedName("rpPairwiseId") @Expose String rpPairwiseId) {}
