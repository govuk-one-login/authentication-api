package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.MFAMethodType;

import java.util.Objects;

public record ResetPasswordRequestHandlerResponse(
        @SerializedName("mfaMethodType") @Expose @NotNull MFAMethodType mfaMethodType,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree) {

    public ResetPasswordRequestHandlerResponse {
        Objects.requireNonNull(mfaMethodType);
    }
}
