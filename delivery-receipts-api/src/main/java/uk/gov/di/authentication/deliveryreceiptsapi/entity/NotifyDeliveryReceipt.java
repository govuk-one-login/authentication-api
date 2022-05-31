package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class NotifyDeliveryReceipt {

    @Expose @Required private String id;

    @Expose private String reference;

    @Expose @Required private String to;

    @Expose @Required private String status;

    @Expose @Required private String createdAt;

    @Expose @Required private String completedAt;

    @Expose @Required private String sentAt;

    @Expose @Required private String notificationType;

    @Expose @Required private String templateId;

    @Expose @Required private int templateVersion;

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
