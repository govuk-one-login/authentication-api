package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public record CheckEmailFraudBlockResponse(
        @SerializedName("email") @Expose @NotNull String email,
        @SerializedName("isBlockedStatus") @Expose String isBlockedStatus) {

    public CheckEmailFraudBlockResponse {
        Objects.requireNonNull(email);
    }
}
