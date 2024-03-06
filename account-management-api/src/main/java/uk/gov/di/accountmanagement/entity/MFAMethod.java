package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record MFAMethod(
        @Expose @Required @SerializedName("mfaIdentifier") String mfaIdentifier,
        @Expose @Required @SerializedName("priorityIdentifier") String priorityIdentifier,
        @Expose @Required @SerializedName("mfaMethodType") String mfaMethodType,
        @Expose @Required @SerializedName("endpoint") String endpoint,
        @Expose @Required @SerializedName("methodVerified") boolean methodVerified) {}
