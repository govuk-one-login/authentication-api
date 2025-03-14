package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

public record ResetPasswordRequestHandlerResponse(
        @SerializedName("mfaMethodType") @Expose @Required MFAMethodType mfaMethodType,
        @SerializedName("phoneNumberLastThree") @Expose String phoneNumberLastThree) {}
