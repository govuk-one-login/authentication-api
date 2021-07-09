package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.NotificationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static uk.gov.di.entity.NotificationType.MFA_SMS;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

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
                                    configService.getNotificationTemplateId(VERIFY_EMAIL));
                            break;
                        case VERIFY_PHONE_NUMBER:
                            Map<String, Object> textPersonalisation = new HashMap<>();
                            textPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    textPersonalisation,
                                    configService.getNotificationTemplateId(VERIFY_PHONE_NUMBER));
                            break;
                        case MFA_SMS:
                            Map<String, Object> mfaPersonalisation = new HashMap<>();
                            mfaPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    mfaPersonalisation,
                                    configService.getNotificationTemplateId(MFA_SMS));
                            break;
                    }
                } catch (NotificationClientException e) {
                    throw new RuntimeException(
                            format(
                                    "Error sending with Notify using NotificationType: %s",
                                    notifyRequest.getNotificationType()),
                            e);
                }
            } catch (JsonProcessingException e) {
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest", e);
            }
        }
        return null;
    }
}
