package uk.gov.di.accountmanagement.services;

import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

public class NotificationService {

    private final NotificationClient notifyClient;
    private final ConfigurationService configurationService;

    public NotificationService(
            NotificationClient notifyClient, ConfigurationService configurationService) {
        this.notifyClient = notifyClient;
        this.configurationService = configurationService;
    }

    public void sendEmail(
            String email,
            Map<String, Object> personalisation,
            NotificationType notificationType,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        notifyClient.sendEmail(
                notificationType.getTemplateId(userLanguage, configurationService),
                email,
                personalisation,
                "");
    }

    public void sendText(
            String phoneNumber,
            Map<String, Object> personalisation,
            NotificationType notificationType,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        notifyClient.sendSms(
                notificationType.getTemplateId(userLanguage, configurationService),
                phoneNumber,
                personalisation,
                "");
    }
}
