package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record CheckEmailFraudBlockResponse(
        @SerializedName("email") @Expose String email,
        @SerializedName("isBlockedStatus") @Expose String isBlockedStatus) {}
