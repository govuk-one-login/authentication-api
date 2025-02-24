package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodCreateRequest(
        @Expose @SerializedName("mfaMethod") @Required MfaMethod mfaMethod) {}

record MfaMethod(
        @Expose @SerializedName("priorityIdentifier") @Required String priorityIdentifier,
        @Expose @SerializedName("method") @Required Method method) {}

record Method(
        @Expose @SerializedName("mfaMethodType") @Required MFAMethodType mfaMethodType,
        @Expose @SerializedName("credential") @Required String credential) {}
