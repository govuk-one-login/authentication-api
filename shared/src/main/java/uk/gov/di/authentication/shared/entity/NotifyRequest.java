package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.validation.Required;

public class NotifyRequest {

    @Expose
    @SerializedName("notificationType")
    @Required
    private NotificationType notificationType;

    @Expose @Required private String destination;

    @Expose private String code;

    @Expose private SupportedLanguage language;

    public NotifyRequest() {}

    public NotifyRequest(
            String destination,
            NotificationType notificationType,
            String code,
            SupportedLanguage language) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
        this.language = language;
    }

    public NotifyRequest(
            String destination, NotificationType notificationType, SupportedLanguage language) {
        this(destination, notificationType, null, language);
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

    public SupportedLanguage getLanguage() {
        return language;
    }
}
