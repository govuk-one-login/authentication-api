package uk.gov.di.accountmanagement.lambda;

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

import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationHandler.class);
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
                LOGGER.info("Message received from SQS queue");
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                try {
                    switch (notifyRequest.getNotificationType()) {
                        case VERIFY_EMAIL:
                            Map<String, Object> emailPersonalisation = new HashMap<>();
                            emailPersonalisation.put("validation-code", notifyRequest.getCode());
                            emailPersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            LOGGER.info("Sending email using Notify");
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    emailPersonalisation,
                                    notificationService.getNotificationTemplateId(VERIFY_EMAIL));
                            break;
                    }
                } catch (NotificationClientException e) {
                    LOGGER.error("Error sending with Notify", e);
                    throw new RuntimeException(
                            String.format(
                                    "Error sending with Notify using NotificationType: %s",
                                    notifyRequest.getNotificationType()),
                            e);
                }
            } catch (JsonProcessingException e) {
                LOGGER.error("Error when mapping message from queue to a NotifyReques", e);
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest", e);
            }
        }
        return null;
    }
}
