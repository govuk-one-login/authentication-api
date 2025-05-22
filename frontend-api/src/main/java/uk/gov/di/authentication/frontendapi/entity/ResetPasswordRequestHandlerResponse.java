package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;

public record ResetPasswordRequestHandlerResponse(
        @SerializedName("mfaMethodType") @Expose @Required MFAMethodType mfaMethodType,
        @SerializedName("mfaMethods") @Expose @Required List<MfaMethodResponse> mfaMethodResponses,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree) {}
