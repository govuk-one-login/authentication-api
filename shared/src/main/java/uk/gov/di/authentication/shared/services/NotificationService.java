package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.TemplateAware;
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
            String email, Map<String, Object> personalisation, TemplateAware type, String reference)
            throws NotificationClientException {
        LOG.info("Sending EMAIL using Notify, reference: {}", reference);
        var sendEmailResponse =
                notifyClient.sendEmail(
                        type.getTemplateId(configurationService),
                        email,
                        personalisation,
                        reference);
        LOG.info(
                "Sent EMAIL using Notify, reference: {}, notification ID: {}",
                reference,
                sendEmailResponse.getNotificationId().toString());
    }

    public void sendText(
            String phoneNumber,
            Map<String, Object> personalisation,
            TemplateAware type,
            String reference)
            throws NotificationClientException {
        LOG.info("Sending SMS using Notify, reference: {}", reference);
        var sendSmsResponse =
                notifyClient.sendSms(
                        type.getTemplateId(configurationService),
                        phoneNumber,
                        personalisation,
                        reference);
        LOG.info(
                "Sent SMS using Notify, reference: {}, notification ID: {}",
                reference,
                sendSmsResponse.getNotificationId().toString());
    }
}
