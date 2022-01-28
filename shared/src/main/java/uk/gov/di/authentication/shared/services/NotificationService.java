package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

public class NotificationService {

    private final NotificationClient notifyClient;

    public NotificationService(NotificationClient notifyClient) {
        this.notifyClient = notifyClient;
    }

    public void sendEmail(String email, Map<String, Object> personalisation, TemplateAware type)
            throws NotificationClientException {
        notifyClient.sendEmail(type.getTemplateId(), email, personalisation, "");
    }

    public void sendText(
            String phoneNumber, Map<String, Object> personalisation, TemplateAware type)
            throws NotificationClientException {
        notifyClient.sendSms(type.getTemplateId(), phoneNumber, personalisation, "");
    }
}
