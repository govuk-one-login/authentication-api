package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class NotifyRequest {

    @Expose
    @SerializedName("notificationType")
    @NotNull
    private NotificationType notificationType;

    @Expose @NotNull private String destination;

    @Expose private String code;

    public NotifyRequest() {}

    public NotifyRequest(String destination, NotificationType notificationType, String code) {
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
