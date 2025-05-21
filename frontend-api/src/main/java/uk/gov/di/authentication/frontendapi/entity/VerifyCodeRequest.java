package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.validation.Required;

public record VerifyCodeRequest(
        @SerializedName("notificationType") @Expose @Required NotificationType notificationType,
        @SerializedName("code") @Expose @Required String code,
        @SerializedName("journeyType") @Expose JourneyType journeyType,
        @SerializedName("mfaMethodId") @Expose String mfaMethodId) {}
