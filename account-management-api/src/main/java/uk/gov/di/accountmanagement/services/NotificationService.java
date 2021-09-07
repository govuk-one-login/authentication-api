package uk.gov.di.accountmanagement.services;

import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

public class NotificationService {

    private final NotificationClient notifyClient;

    public NotificationService(NotificationClient notifyClient) {
        this.notifyClient = notifyClient;
    }

    public void sendEmail(String email, Map<String, Object> personalisation, String templateId)
            throws NotificationClientException {
        notifyClient.sendEmail(templateId, email, personalisation, "");
    }

    public void sendText(String phoneNumber, Map<String, Object> personalisation, String templateId)
            throws NotificationClientException {
        notifyClient.sendSms(templateId, phoneNumber, personalisation, "");
    }

    public String getNotificationTemplateId(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return System.getenv("VERIFY_EMAIL_TEMPLATE_ID");
            case VERIFY_PHONE_NUMBER:
                return System.getenv("VERIFY_PHONE_NUMBER_TEMPLATE_ID");
            case EMAIL_UPDATED:
                return System.getenv("EMAIL_UPDATED_TEMPLATE_ID");
            case DELETE_ACCOUNT:
                return System.getenv("DELETE_ACCOUNT_TEMPLATE_ID");
            case PHONE_NUMBER_UPDATED:
                return System.getenv("PHONE_NUMBER_UPDATED_TEMPLATE_ID");
            case PASSWORD_UPDATED:
                return System.getenv("PASSWORD_UPDATED_TEMPLATE_ID");
            default:
                throw new RuntimeException("NotificationType template ID does not exist");
        }
    }
}
