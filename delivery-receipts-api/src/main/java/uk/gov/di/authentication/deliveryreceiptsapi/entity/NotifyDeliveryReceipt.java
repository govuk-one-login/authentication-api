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
    private String created_at;

    @JsonProperty("completed_at")
    private String completed_at;

    @JsonProperty("sent_at")
    private String sent_at;

    @JsonProperty("notification_type")
    private String notification_type;

    @JsonProperty("template_id")
    private String template_id;

    @JsonProperty("template_version")
    private int template_version;

    public NotifyDeliveryReceipt(
            @JsonProperty(required = true, value = "id") String id,
            @JsonProperty(required = true, value = "reference") String reference,
            @JsonProperty(required = true, value = "to") String to,
            @JsonProperty(required = true, value = "status") String status,
            @JsonProperty(required = true, value = "created_at") String created_at,
            @JsonProperty(required = true, value = "completed_at") String completed_at,
            @JsonProperty(required = true, value = "sent_at") String sent_at,
            @JsonProperty(required = true, value = "notification_type") String notification_type,
            @JsonProperty(required = true, value = "template_id") String template_id,
            @JsonProperty(required = true, value = "template_version") int template_version) {
        this.id = id;
        this.reference = reference;
        this.to = to;
        this.status = status;
        this.created_at = created_at;
        this.completed_at = completed_at;
        this.sent_at = sent_at;
        this.notification_type = notification_type;
        this.template_id = template_id;
        this.template_version = template_version;
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

    public String getCreated_at() {
        return created_at;
    }

    public String getCompleted_at() {
        return completed_at;
    }

    public String getSent_at() {
        return sent_at;
    }

    public String getNotification_type() {
        return notification_type;
    }

    public String getTemplate_id() {
        return template_id;
    }

    public int getTemplate_version() {
        return template_version;
    }
}
