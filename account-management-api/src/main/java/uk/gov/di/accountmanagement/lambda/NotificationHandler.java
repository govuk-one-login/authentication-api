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
        try {
            Map<String, Object> emailPersonalisation = new HashMap<>();
            emailPersonalisation.put("validation-code", notifyRequest.getCode());
            emailPersonalisation.put("email-address", notifyRequest.getDestination());
            emailPersonalisation.put("contact-us-link", buildContactUsUrl());
            LOG.info("Sending VERIFY_EMAIL email using Notify");
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    emailPersonalisation,
                    NotificationType.VERIFY_EMAIL);
            LOG.info("VERIFY_EMAIL email has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending VERIFY_EMAIL email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending VERIFY_EMAIL email with notify", e);
            return false;
        }
    }

    private boolean sendVerifyPhoneNotification(NotifyRequest notifyRequest) {
        try {
            Map<String, Object> phonePersonalisation = new HashMap<>();
            phonePersonalisation.put("validation-code", notifyRequest.getCode());
            LOG.info("Sending VERIFY_PHONE_NUMBER email using Notify");
            notificationService.sendText(
                    notifyRequest.getDestination(),
                    phonePersonalisation,
                    NotificationType.VERIFY_PHONE_NUMBER);
            LOG.info("VERIFY_PHONE_NUMBER text has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending VERIFY_PHONE_NUMBER email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending VERIFY_PHONE_NUMBER email with notify", e);
            return false;
        }
    }

    private boolean sendEmailUpdatedNotification(NotifyRequest notifyRequest) {
        try {
            Map<String, Object> emailUpdatePersonalisation = new HashMap<>();
            emailUpdatePersonalisation.put("email-address", notifyRequest.getDestination());
            emailUpdatePersonalisation.put("contact-us-link", buildContactUsUrl());
            LOG.info("Sending EMAIL_UPDATED email using Notify");
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    emailUpdatePersonalisation,
                    NotificationType.EMAIL_UPDATED);
            LOG.info("EMAIL_UPDATED email has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending EMAIL_UPDATED email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending EMAIL_UPDATED email with notify", e);
            return false;
        }
    }

    private boolean sendDeleteAccountNotification(NotifyRequest notifyRequest) {
        try {
            LOG.info("Sending DELETE_ACCOUNT email using Notify");
            Map<String, Object> accountDeletedPersonalisation = new HashMap<>();
            accountDeletedPersonalisation.put("contact-us-link", buildContactUsUrl());
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    accountDeletedPersonalisation,
                    NotificationType.DELETE_ACCOUNT);
            LOG.info("DELETE_ACCOUNT email has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending DELETE_ACCOUNT email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending DELETE_ACCOUNT email with notify", e);
            return false;
        }
    }

    private boolean sendPhoneNumberUpdatedNotification(NotifyRequest notifyRequest) {
        try {
            LOG.info("Sending PHONE_NUMBER_UPDATED email using Notify");
            Map<String, Object> phoneNumberUpdatedPersonalisation = new HashMap<>();
            phoneNumberUpdatedPersonalisation.put("contact-us-link", buildContactUsUrl());
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    phoneNumberUpdatedPersonalisation,
                    NotificationType.PHONE_NUMBER_UPDATED);
            LOG.info("PHONE_NUMBER_UPDATED email has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending PHONE_NUMBER_UPDATED email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending PHONE_NUMBER_UPDATED email with notify", e);
            return false;
        }
    }

    private boolean sendPasswordUpdatedNotification(NotifyRequest notifyRequest)
            throws NotificationClientException {
        try {
            LOG.info("Sending PASSWORD_UPDATED email using Notify");
            Map<String, Object> passwordUpdatedPersonalisation = new HashMap<>();
            passwordUpdatedPersonalisation.put("contact-us-link", buildContactUsUrl());
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    passwordUpdatedPersonalisation,
                    NotificationType.PASSWORD_UPDATED);
            LOG.info("PASSWORD_UPDATED email has been sent using Notify");
            return true;
        } catch (NotificationClientException e) {
            LOG.error("Error sending PASSWORD_UPDATED email with notify", e);
            return false;
        } catch (RuntimeException e) {
            LOG.error("Unexpected error sending PASSWORD_UPDATED email with notify", e);
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
