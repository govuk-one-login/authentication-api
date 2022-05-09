package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.NotificationService;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);
    private final NotificationService notificationService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    private final ConfigurationService configurationService;

    public NotificationHandler(
            NotificationService notificationService, ConfigurationService configService) {
        this.notificationService = notificationService;
        this.configurationService = configService;
    }

    public NotificationHandler() {
        this(ConfigurationService.getInstance());
    }

    public NotificationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        NotificationClient client =
                this.configurationService
                        .getNotifyApiUrl()
                        .map(
                                url ->
                                        new NotificationClient(
                                                this.configurationService.getNotifyApiKey(), url))
                        .orElse(
                                new NotificationClient(
                                        this.configurationService.getNotifyApiKey()));
        this.notificationService = new NotificationService(client);
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> notificationRequestHandler(event, context));
    }

    public Void notificationRequestHandler(SQSEvent event, Context context) {

        for (SQSMessage msg : event.getRecords()) {
            try {
                LOG.info("Message received from SQS queue");
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                try {
                    switch (notifyRequest.getNotificationType()) {
                        case VERIFY_EMAIL:
                            Map<String, Object> emailPersonalisation = new HashMap<>();
                            emailPersonalisation.put("validation-code", notifyRequest.getCode());
                            emailPersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            emailPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("confirmEmailAddressEmail"));
                            LOG.info("Sending VERIFY_EMAIL email using Notify");
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    emailPersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.VERIFY_EMAIL));
                            LOG.info("VERIFY_EMAIL email has been sent using Notify");
                            break;
                        case VERIFY_PHONE_NUMBER:
                            Map<String, Object> phonePersonalisation = new HashMap<>();
                            phonePersonalisation.put("validation-code", notifyRequest.getCode());
                            LOG.info("Sending VERIFY_PHONE_NUMBER email using Notify");
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    phonePersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.VERIFY_PHONE_NUMBER));
                            LOG.info("VERIFY_PHONE_NUMBER text has been sent using Notify");
                            break;
                        case EMAIL_UPDATED:
                            Map<String, Object> emailUpdatePersonalisation = new HashMap<>();
                            emailUpdatePersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            emailUpdatePersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("emailAddressUpdatedEmail"));
                            LOG.info("Sending EMAIL_UPDATED email using Notify");
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    emailUpdatePersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.EMAIL_UPDATED));
                            LOG.info("EMAIL_UPDATED email has been sent using Notify");
                            break;
                        case DELETE_ACCOUNT:
                            LOG.info("Sending DELETE_ACCOUNT email using Notify");
                            Map<String, Object> accountDeletedPersonalisation = new HashMap<>();
                            accountDeletedPersonalisation.put(
                                    "contact-us-link", buildContactUsUrl("accountDeletedEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    accountDeletedPersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.DELETE_ACCOUNT));
                            LOG.info("DELETE_ACCOUNT email has been sent using Notify");
                            break;
                        case PHONE_NUMBER_UPDATED:
                            LOG.info("Sending PHONE_NUMBER_UPDATED email using Notify");
                            Map<String, Object> phoneNumberUpdatedPersonalisation = new HashMap<>();
                            phoneNumberUpdatedPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("phoneNumberUpdatedEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    phoneNumberUpdatedPersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.PHONE_NUMBER_UPDATED));
                            LOG.info("PHONE_NUMBER_UPDATED email has been sent using Notify");
                            break;
                        case PASSWORD_UPDATED:
                            LOG.info("Sending PASSWORD_UPDATED email using Notify");
                            Map<String, Object> passwordUpdatedPersonalisation = new HashMap<>();
                            passwordUpdatedPersonalisation.put(
                                    "contact-us-link", buildContactUsUrl("passwordUpdatedEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    passwordUpdatedPersonalisation,
                                    notificationService.getNotificationTemplateId(
                                            NotificationType.PASSWORD_UPDATED));
                            LOG.info("PASSWORD_UPDATED email has been sent using Notify");
                            break;
                    }
                } catch (NotificationClientException e) {
                    LOG.error("Error sending with Notify", e);
                    throw new RuntimeException(
                            String.format(
                                    "Error sending with Notify using NotificationType: %s",
                                    notifyRequest.getNotificationType()),
                            e);
                }
            } catch (JsonProcessingException e) {
                LOG.error("Error when mapping message from queue to a NotifyRequest");
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest");
            }
        }
        return null;
    }

    private String buildContactUsUrl(String referer) {
        var queryParam = Map.of("referer", referer);
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getContactUsLinkRoute(),
                        queryParam)
                .toString();
    }
}
