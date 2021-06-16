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

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private NotificationService notificationService;
    private ObjectMapper objectMapper = new ObjectMapper();
    private ConfigurationService configService;
    private NotificationClient client =
            new NotificationClient(new ConfigurationService().getNotifyApiKey());

    public NotificationHandler(
            NotificationService notificationService, ConfigurationService configService) {
        this.notificationService = notificationService;
        this.configService = configService;
    }

    public NotificationHandler() {
        this.notificationService = new NotificationService(client);
        this.configService = new ConfigurationService();
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {

        for (SQSMessage msg : event.getRecords()) {
            try {
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                switch (notifyRequest.getNotificationType()) {
                    case VERIFY_EMAIL:
                        Random rnd = new Random();
                        String number = Integer.toString(rnd.nextInt(999999));
                        Map<String, Object> personalisation = new HashMap<>();
                        personalisation.put("validation-code", number);
                        personalisation.put("email-address", notifyRequest.getDestination());
                        notificationService.sendEmail(
                                notifyRequest.getDestination(),
                                personalisation,
                                configService.getNotificationTemplateId(VERIFY_EMAIL));
                        break;
                }
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
        return null;
    }
}
