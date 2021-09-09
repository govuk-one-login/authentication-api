package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LoggerFactory.getLogger(NotificationHandler.class);

    private final NotificationService notificationService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ConfigurationService configService;

    public NotificationHandler(
            NotificationService notificationService, ConfigurationService configService) {
        this.notificationService = notificationService;
        this.configService = configService;
    }

    public NotificationHandler() {
        this.configService = new ConfigurationService();
        NotificationClient client =
                configService
                        .getNotifyApiUrl()
                        .map(url -> new NotificationClient(configService.getNotifyApiKey(), url))
                        .orElse(new NotificationClient(configService.getNotifyApiKey()));
        this.notificationService = new NotificationService(client);
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {

        for (SQSMessage msg : event.getRecords()) {
            try {
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                try {
                    switch (notifyRequest.getNotificationType()) {
                        case VERIFY_EMAIL:
                            Map<String, Object> emailPersonalisation = new HashMap<>();
                            emailPersonalisation.put("validation-code", notifyRequest.getCode());
                            emailPersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    emailPersonalisation,
                                    notificationService.getNotificationTemplateId(VERIFY_EMAIL));
                            break;
                        case VERIFY_PHONE_NUMBER:
                            Map<String, Object> textPersonalisation = new HashMap<>();
                            textPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    textPersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            VERIFY_PHONE_NUMBER));
                            break;
                        case MFA_SMS:
                            Map<String, Object> mfaPersonalisation = new HashMap<>();
                            mfaPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    mfaPersonalisation,
                                    notificationService.getNotificationTemplateId(MFA_SMS));
                            break;
                    }
                } catch (NotificationClientException e) {
                    LOG.error(
                            "Error sending with Notify using NotificationType: {}",
                            notifyRequest.getNotificationType(),
                            e);
                    throw new RuntimeException(
                            String.format(
                                    "Error sending with Notify using NotificationType: %s",
                                    notifyRequest.getNotificationType()),
                            e);
                }
            } catch (JsonProcessingException e) {
                LOG.error("Error when mapping message from queue to a NotifyRequest", e);
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest", e);
            }
        }
        return null;
    }
}
