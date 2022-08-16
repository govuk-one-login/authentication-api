package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class NotifyRequest {

    @Expose
    @SerializedName("notificationType")
    @Required
    private NotificationType notificationType;

    @Expose @Required private String destination;

    @Expose private String code;

    @Expose private String language;

    public NotifyRequest() {}

    public NotifyRequest(String destination, NotificationType notificationType, String code) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
    }

    public NotifyRequest(String destination, NotificationType notificationType) {
        this(destination, notificationType, null);
    }

    public NotifyRequest(
            NotificationType notificationType, String destination, String code, String language) {
        this(destination, notificationType, code);
        this.language = language;
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

    public String getLanguage() {
        return language;
    }
}
