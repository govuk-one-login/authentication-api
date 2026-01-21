package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;

public record ResetPasswordRequestHandlerResponse(
        @SerializedName("mfaMethodType") @Expose MFAMethodType mfaMethodType,
        @SerializedName("mfaMethods") @Expose List<MfaMethodResponse> mfaMethodResponses,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree) {}
