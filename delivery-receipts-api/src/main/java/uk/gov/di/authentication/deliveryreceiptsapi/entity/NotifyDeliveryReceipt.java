package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NotifyDeliveryReceipt {

    @JsonProperty("id")
    private String id;

    @JsonProperty("reference")
    private String reference;

    @JsonProperty("to")
    private String to;

    @JsonProperty("status")
    private String status;

    @JsonProperty("created_at")
    private String createdAt;

    @JsonProperty("completed_at")
    private String completedAt;

    @JsonProperty("sent_at")
    private String sentAt;

    @JsonProperty("notification_type")
    private String notificationType;

    @JsonProperty("template_id")
    private String templateId;

    @JsonProperty("template_version")
    private int templateVersion;

    public NotifyDeliveryReceipt(
            @JsonProperty(required = true, value = "id") String id,
            @JsonProperty(required = true, value = "reference") String reference,
            @JsonProperty(required = true, value = "to") String to,
            @JsonProperty(required = true, value = "status") String status,
            @JsonProperty(required = true, value = "created_at") String createdAt,
            @JsonProperty(required = true, value = "completed_at") String completedAt,
            @JsonProperty(required = true, value = "sent_at") String sentAt,
            @JsonProperty(required = true, value = "notification_type") String notificationType,
            @JsonProperty(required = true, value = "template_id") String templateId,
            @JsonProperty(required = true, value = "template_version") int templateVersion) {
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
