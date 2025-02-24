package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;

public record MfaMethodCreateRequest(@Expose @SerializedName("mfaMethod") MfaMethod mfaMethod) {
    public record MfaMethod(
            @Expose @SerializedName("priorityIdentifier") String priorityIdentifier,
            @Expose @SerializedName("method") Method method) {
        public record Method(
                @Expose @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
                @Expose @SerializedName("credential") String credential) {}
    }
}
