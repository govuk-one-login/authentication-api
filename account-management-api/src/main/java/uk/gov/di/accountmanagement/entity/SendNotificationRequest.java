package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.authentication.shared.entity.NotificationType;

public class SendNotificationRequest {

    private final NotificationType notificationType;
    private final String phoneNumber;
    private final String email;

    public SendNotificationRequest(
            @JsonProperty(required = true, value = "email") String email,
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType,
            @JsonProperty(value = "phoneNumber") String phoneNumber) {
        this.email = email;
        this.notificationType = notificationType;
        this.phoneNumber = phoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    @Override
    public String toString() {
        return "SendNotificationRequest{"
                + "notificationType="
                + notificationType
                + ", phoneNumber='"
                + phoneNumber
                + '\''
                + ", email='"
                + email
                + '\''
                + '}';
    }
}
