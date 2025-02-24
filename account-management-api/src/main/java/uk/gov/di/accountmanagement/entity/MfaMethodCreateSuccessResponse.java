package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;

public record MfaMethodCreateSuccessResponse(
        @Expose @SerializedName("mfaIdentifier") int mfaIdentifier,
        @Expose @SerializedName("priorityIdentifier") PriorityIdentifier priorityIdentifier,
        @Expose @SerializedName("method") Method method,
        @Expose @SerializedName("methodVerified") boolean methodVerified) {
    public record Method(
            @Expose @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
            @Expose @SerializedName("phoneNumber") String phoneNumber) {}
}
