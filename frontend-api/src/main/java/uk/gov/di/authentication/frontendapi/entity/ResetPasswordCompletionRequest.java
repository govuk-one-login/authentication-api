package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record ResetPasswordCompletionRequest(
        @SerializedName("password") @Expose @Required String password,
        @SerializedName("isForcedPasswordReset") @Expose @Required boolean isForcedPasswordReset,
        @SerializedName("allowMfaResetAfterPasswordReset") @Expose
                boolean allowMfaResetAfterPasswordReset) {}
