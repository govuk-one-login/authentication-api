package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class SendNotificationRequest {

    @Expose
    @SerializedName("notificationType")
    @Required
    private NotificationType notificationType;

    @Expose
    @SerializedName("phoneNumber")
    private String phoneNumber;

    @Expose @Required private String email;

    public SendNotificationRequest() {}

    public SendNotificationRequest(
            String email, NotificationType notificationType, String phoneNumber) {
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
