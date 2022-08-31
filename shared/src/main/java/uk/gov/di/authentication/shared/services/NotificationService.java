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

    public NotificationService(NotificationClient notifyClient) {
        this.notifyClient = notifyClient;
    }

    public void sendEmail(
            String email,
            Map<String, Object> personalisation,
            TemplateAware type,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        LOG.info("sendEmail language {}", userLanguage);
        notifyClient.sendEmail(type.getTemplateId(), email, personalisation, "");
    }

    public void sendText(
            String phoneNumber,
            Map<String, Object> personalisation,
            TemplateAware type,
            SupportedLanguage userLanguage)
            throws NotificationClientException {
        LOG.info("sendText language {}", userLanguage);
        notifyClient.sendSms(type.getTemplateId(), phoneNumber, personalisation, "");
    }
}
