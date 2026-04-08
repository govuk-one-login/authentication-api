package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;
import java.util.Objects;

public record ResetPasswordRequestHandlerResponse(
        @SerializedName("mfaMethodType") @Expose MFAMethodType mfaMethodType,
        @SerializedName("mfaMethods") @Expose @NotNull List<MfaMethodResponse> mfaMethodResponses,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree) {

    public ResetPasswordRequestHandlerResponse {
        Objects.requireNonNull(mfaMethodResponses);
    }
}
