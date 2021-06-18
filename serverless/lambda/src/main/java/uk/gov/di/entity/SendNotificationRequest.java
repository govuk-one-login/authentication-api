package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import static java.lang.String.format;

public class SendNotificationRequest extends UserWithEmailRequest {

    private final NotificationType notificationType;

    public SendNotificationRequest(
            @JsonProperty(required = true, value = "email") String email,
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType) {
        super(email);
        this.notificationType = notificationType;
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    @Override
    public String toString() {
        return format(
                "SendNotificationRequest{ email='%s', notificationType = '%s' }",
                email, notificationType);
    }
}
