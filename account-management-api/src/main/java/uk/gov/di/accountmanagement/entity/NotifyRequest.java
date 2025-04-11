package uk.gov.di.accountmanagement.entity;

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

    @Expose private String sessionId;

    @Expose private String clientSessionId;

    @Expose private String email;

    @Expose private boolean isTestClient;

    public NotifyRequest() {}

    public NotifyRequest(
            String destination,
            NotificationType notificationType,
            String code,
            SupportedLanguage language,
            boolean isTestClient,
            String email) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
        this.language = language;
        this.isTestClient = isTestClient;
        this.email = email;
    }

    public NotifyRequest(
            String destination,
            NotificationType notificationType,
            String code,
            SupportedLanguage language,
            String sessionId,
            String clientSessionId) {
        this(destination, notificationType, code, language, false, null);
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
    }

    public NotifyRequest(
            String destination, NotificationType notificationType, SupportedLanguage language) {
        this(destination, notificationType, null, language, false, null);
    }

    public NotifyRequest(
            String destination,
            NotificationType notificationType,
            SupportedLanguage language,
            String sessionId,
            String clientSessionId) {
        this(destination, notificationType, null, language, false, null);
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
    }

    public String getEmail() {
        return email;
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

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public boolean isTestClient() {
        return isTestClient;
    }

    @Override
    public String toString() {
        return "NotifyRequest{"
                + "clientSessionId='"
                + clientSessionId
                + '\''
                + ", notificationType="
                + notificationType
                + ", destination='"
                + destination
                + '\''
                + ", code='"
                + code
                + '\''
                + ", language="
                + language
                + ", sessionId='"
                + sessionId
                + '\''
                + ", isTestClient="
                + isTestClient
                + '}';
    }
}
