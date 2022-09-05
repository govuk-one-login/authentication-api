package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

public class NotificationService {

    private static final Logger LOG = LogManager.getLogger(NotificationService.class);

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
            TemplateAware type,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        LOG.info("sendEmail language {}", userLanguage);
        notifyClient.sendEmail(
                type.getTemplateId(userLanguage, configurationService), email, personalisation, "");
    }

    public void sendText(
            String phoneNumber,
            Map<String, Object> personalisation,
            TemplateAware type,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        LOG.info("sendText language {}", userLanguage);
        notifyClient.sendSms(
                type.getTemplateId(userLanguage, configurationService),
                phoneNumber,
                personalisation,
                "");
    }
}
