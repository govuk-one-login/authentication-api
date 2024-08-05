package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record NotifyDeliveryReceipt(
        @Expose @Required String id,
        @Expose String reference,
        @Expose @Required String to,
        @Expose @Required String status,
        @Expose @Required String createdAt,
        @Expose String completedAt,
        @Expose String sentAt,
        @Expose @Required String notificationType,
        @Expose @Required String templateId,
        @Expose @Required int templateVersion) {}
