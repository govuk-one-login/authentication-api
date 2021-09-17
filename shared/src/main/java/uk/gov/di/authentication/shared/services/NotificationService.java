package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.NotificationType;
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
            case MFA_SMS:
                return System.getenv("MFA_SMS_TEMPLATE_ID");
            case RESET_PASSWORD:
                return System.getenv("RESET_PASSWORD_TEMPLATE_ID");
            case PASSWORD_RESET_CONFIRMATION:
                return System.getenv("PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID");
            default:
                throw new RuntimeException("NotificationType template ID does not exist");
        }
    }
}
