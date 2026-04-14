package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.validation.Required;

public record SendNotificationRequest(
        @Expose @SerializedName("notificationType") @Required NotificationType notificationType,
        @Expose @SerializedName("phoneNumber") String phoneNumber,
        @Expose @SerializedName("priorityIdentifier") PriorityIdentifier priorityIdentifier,
        @Expose @Required String email) {}
