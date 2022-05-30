package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class NotifyRequest {

    @Expose
    @SerializedName("notificationType")
    @JsonProperty
    private NotificationType notificationType;

    @Expose @JsonProperty private String destination;

    @Expose @JsonProperty private String code;

    public NotifyRequest(
            @JsonProperty(required = true, value = "destination") String destination,
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType,
            @JsonProperty(value = "code") String code) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
    }

    public NotifyRequest(String destination, NotificationType notificationType) {
        this(destination, notificationType, null);
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getDestination() {
        return destination;
    }

    public String getCode() {
        return code;
    }
}
