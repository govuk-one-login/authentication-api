package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;

public class NotifyDeliveryReceipt {

    @Expose @NotNull private String id;

    @Expose private String reference;

    @Expose @NotNull private String to;

    @Expose @NotNull private String status;

    @Expose @NotNull private String createdAt;

    @Expose @NotNull private String completedAt;

    @Expose @NotNull private String sentAt;

    @Expose @NotNull private String notificationType;

    @Expose @NotNull private String templateId;

    @Expose @NotNull private int templateVersion;

    public NotifyDeliveryReceipt() {}

    public NotifyDeliveryReceipt(
            String id,
            String reference,
            String to,
            String status,
            String createdAt,
            String completedAt,
            String sentAt,
            String notificationType,
            String templateId,
            int templateVersion) {
        this.id = id;
        this.reference = reference;
        this.to = to;
        this.status = status;
        this.createdAt = createdAt;
        this.completedAt = completedAt;
        this.sentAt = sentAt;
        this.notificationType = notificationType;
        this.templateId = templateId;
        this.templateVersion = templateVersion;
    }

    public String getId() {
        return id;
    }

    public String getReference() {
        return reference;
    }

    public String getTo() {
        return to;
    }

    public String getStatus() {
        return status;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public String getCompletedAt() {
        return completedAt;
    }

    public String getSentAt() {
        return sentAt;
    }

    public String getNotificationType() {
        return notificationType;
    }

    public String getTemplateId() {
        return templateId;
    }

    public int getTemplateVersion() {
        return templateVersion;
    }
}
