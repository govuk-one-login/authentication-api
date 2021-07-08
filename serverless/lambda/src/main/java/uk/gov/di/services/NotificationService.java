package uk.gov.di.services;

import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

public class NotificationService {

    private NotificationClient notifyClient;

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
}
