package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.NotificationService;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);
    private final NotificationService notificationService;
    private final Json objectMapper = SerializationService.getInstance();
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
        this.notificationService = new NotificationService(client, configurationService);
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
                processMessage(msg);
            } catch (JsonException e) {
                LOG.error("Error when mapping message from queue to a NotifyRequest");
                throw new RuntimeException(
                        "Error when mapping message from queue to a NotifyRequest");
            }
        }
        return null;
    }

    private void processMessage(SQSMessage msg) throws JsonException {
        LOG.info("Message received from SQS queue");
        NotifyRequest notifyRequest = objectMapper.readValue(msg.getBody(), NotifyRequest.class);
        try {
            sendNotification(notifyRequest);
        } catch (NotificationClientException e) {
            LOG.error("Error sending with Notify", e);
            throw new RuntimeException(
                    String.format(
                            "Error sending with Notify using NotificationType: %s",
                            notifyRequest.getNotificationType()),
                    e);
        }
    }

    private void sendNotification(NotifyRequest notifyRequest) throws NotificationClientException {
        boolean success =
                switch (notifyRequest.getNotificationType()) {
                    case VERIFY_EMAIL -> sendVerifyEmailNotification(notifyRequest);
                    case VERIFY_PHONE_NUMBER -> sendVerifyPhoneNotification(notifyRequest);
                    case EMAIL_UPDATED -> sendEmailUpdatedNotification(notifyRequest);
                    case DELETE_ACCOUNT -> sendDeleteAccountNotification(notifyRequest);
                    case PHONE_NUMBER_UPDATED -> sendPhoneNumberUpdatedNotification(notifyRequest);
                    case PASSWORD_UPDATED -> sendPasswordUpdatedNotification(notifyRequest);
                };

        if (!success) {
            LOG.error(
                    "Failed to send notification of type {}", notifyRequest.getNotificationType());
            throw new RuntimeException(
                    String.format(
                            "Error sending with Notify using NotificationType: %s",
                            notifyRequest.getNotificationType()));
        }
    }

    private boolean sendVerifyEmailNotification(NotifyRequest notifyRequest) {
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put("validation-code", notifyRequest.getCode());
        emailPersonalisation.put("email-address", notifyRequest.getDestination());
        emailPersonalisation.put("contact-us-link", buildContactUsUrl());
        return sendEmailNotification(
                notifyRequest, emailPersonalisation, String.valueOf(NotificationType.VERIFY_EMAIL));
    }

    private boolean sendVerifyPhoneNotification(NotifyRequest notifyRequest) {
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put("validation-code", notifyRequest.getCode());
        return sendTextNotification(notifyRequest, phonePersonalisation, String.valueOf(NotificationType.VERIFY_PHONE_NUMBER));
    }

    private boolean sendEmailUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> emailUpdatePersonalisation = new HashMap<>();
        emailUpdatePersonalisation.put("email-address", notifyRequest.getDestination());
        emailUpdatePersonalisation.put("contact-us-link", buildContactUsUrl());
        return sendEmailNotification(notifyRequest, emailUpdatePersonalisation, String.valueOf(NotificationType.EMAIL_UPDATED));
    }

    private boolean sendDeleteAccountNotification(NotifyRequest notifyRequest) {
        Map<String, Object> accountDeletedPersonalisation = new HashMap<>();
        accountDeletedPersonalisation.put("contact-us-link", buildContactUsUrl());
        return sendEmailNotification(notifyRequest, accountDeletedPersonalisation, String.valueOf(NotificationType.DELETE_ACCOUNT));
    }

    private boolean sendPhoneNumberUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> phoneNumberUpdatedPersonalisation = new HashMap<>();
        phoneNumberUpdatedPersonalisation.put("contact-us-link", buildContactUsUrl());
        return sendEmailNotification(notifyRequest, phoneNumberUpdatedPersonalisation, String.valueOf(NotificationType.PHONE_NUMBER_UPDATED));
    }

    private boolean sendPasswordUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> passwordUpdatedPersonalisation = new HashMap<>();
        passwordUpdatedPersonalisation.put("contact-us-link", buildContactUsUrl());
        return sendEmailNotification(notifyRequest, passwordUpdatedPersonalisation, String.valueOf(NotificationType.PASSWORD_UPDATED));
    }

    private boolean sendEmailNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        try {
            LOG.info("Sending %s email using Notify", notificationType);
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    personalisation,
                    NotificationType.valueOf(notificationType));
            LOG.info("%s email has been sent using Notify", notificationType);
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending %s email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending %s email with notify", e);
            return false;
        }
    }

    private boolean sendTextNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        try {
            LOG.info("Sending %s text using Notify", notificationType);
            notificationService.sendText(
                    notifyRequest.getDestination(),
                    personalisation,
                    NotificationType.valueOf(notificationType));
            LOG.info("%s text has been sent using Notify", notificationType);
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending with Notify: %s", e.getMessage());
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending %s notification %s", e.getMessage(), notificationType);
            return false;
        }
    }

    private String buildContactUsUrl() {
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getContactUsLinkRoute())
                .toString();
    }
}
