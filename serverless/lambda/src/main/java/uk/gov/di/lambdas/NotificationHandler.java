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

import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;

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
        NotificationClient client = new NotificationClient(configService.getNotifyApiKey());
        this.notificationService = new NotificationService(client);
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {

        for (SQSMessage msg : event.getRecords()) {
            try {
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                switch (notifyRequest.getNotificationType()) {
                    case VERIFY_EMAIL:
                        String code = notificationService.generateSixDigitCode();
                        Map<String, Object> personalisation = new HashMap<>();
                        personalisation.put("validation-code", code);
                        personalisation.put("email-address", notifyRequest.getDestination());
                        notificationService.sendEmail(
                                notifyRequest.getDestination(),
                                personalisation,
                                configService.getNotificationTemplateId(VERIFY_EMAIL));
                        break;
                }
            } catch (JsonProcessingException e) {
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest", e);
            } catch (NotificationClientException e) {
                throw new RuntimeException("Error when sending email via Notify", e);
            }
        }
        return null;
    }
}
