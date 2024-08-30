package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public record UserStartInfo(
        @SerializedName("upliftRequired") @Expose @Required boolean isUpliftRequired,
        @SerializedName("identityRequired") @Expose @Required boolean isIdentityRequired,
        @SerializedName("authenticated") @Expose @Required boolean isAuthenticated,
        @SerializedName("cookieConsent") @Expose String cookieConsent,
        @SerializedName("gaCrossDomainTrackingId") @Expose String gaCrossDomainTrackingId,
        @SerializedName("docCheckingAppUser") @Expose boolean isDocCheckingAppUser,
        @SerializedName("mfaMethodType") @Expose MFAMethodType mfaMethodType,
        @SerializedName("isBlockedForReauth") @Expose boolean isBlockedForReauth) {}
