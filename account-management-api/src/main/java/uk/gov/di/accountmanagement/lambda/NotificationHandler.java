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

import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.CONTACT_US_LINK_PERSONALISATION;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.EMAIL_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.ERROR_SENDING_WITH_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.ERROR_WHEN_MAPPING_MESSAGE_FROM_QUEUE_TO_A_NOTIFY_REQUEST;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.TEXT_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.UNEXPECTED_ERROR_SENDING_NOTIFICATION;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);
    public static final String VALIDATION_CODE_PERSONALISATION = "validation-code";
    public static final String EMAIL_ADDRESS_PERSONALISATION = "email-address";
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
        segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> notificationRequestHandler(event));
        return null;
    }

    public void notificationRequestHandler(SQSEvent event) {
        for (SQSMessage msg : event.getRecords()) {
            processMessage(msg);
        }
    }

    private void processMessage(SQSMessage msg) {
        LOG.info(LogMessageTemplates.MESSAGE_RECEIVED_FROM_SQS_QUEUE);
        try {
            NotifyRequest notifyRequest =
                    objectMapper.readValue(msg.getBody(), NotifyRequest.class);
            sendNotification(notifyRequest);
        } catch (JsonException e) {
            LOG.error(ERROR_WHEN_MAPPING_MESSAGE_FROM_QUEUE_TO_A_NOTIFY_REQUEST);
        }
    }

    private void sendNotification(NotifyRequest notifyRequest) {
        switch (notifyRequest.getNotificationType()) {
            case VERIFY_EMAIL -> sendVerifyEmailNotification(notifyRequest);
            case VERIFY_PHONE_NUMBER -> sendVerifyPhoneNotification(notifyRequest);
            case EMAIL_UPDATED -> sendEmailUpdatedNotification(notifyRequest);
            case DELETE_ACCOUNT -> sendDeleteAccountNotification(notifyRequest);
            case PHONE_NUMBER_UPDATED -> sendPhoneNumberUpdatedNotification(notifyRequest);
            case PASSWORD_UPDATED -> sendPasswordUpdatedNotification(notifyRequest);
        }
    }

    private void sendVerifyEmailNotification(NotifyRequest notifyRequest) {
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put(VALIDATION_CODE_PERSONALISATION, notifyRequest.getCode());
        emailPersonalisation.put(EMAIL_ADDRESS_PERSONALISATION, notifyRequest.getDestination());
        emailPersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(
                notifyRequest, emailPersonalisation, String.valueOf(NotificationType.VERIFY_EMAIL));
    }

    private void sendVerifyPhoneNotification(NotifyRequest notifyRequest) {
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put(VALIDATION_CODE_PERSONALISATION, notifyRequest.getCode());
        sendTextNotification(
                notifyRequest,
                phonePersonalisation,
                String.valueOf(NotificationType.VERIFY_PHONE_NUMBER));
    }

    private void sendEmailUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> emailUpdatePersonalisation = new HashMap<>();
        emailUpdatePersonalisation.put(
                EMAIL_ADDRESS_PERSONALISATION, notifyRequest.getDestination());
        emailUpdatePersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(
                notifyRequest,
                emailUpdatePersonalisation,
                String.valueOf(NotificationType.EMAIL_UPDATED));
    }

    private void sendDeleteAccountNotification(NotifyRequest notifyRequest) {
        Map<String, Object> accountDeletedPersonalisation = new HashMap<>();
        accountDeletedPersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(
                notifyRequest,
                accountDeletedPersonalisation,
                String.valueOf(NotificationType.DELETE_ACCOUNT));
    }

    private void sendPhoneNumberUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> phoneNumberUpdatedPersonalisation = new HashMap<>();
        phoneNumberUpdatedPersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(
                notifyRequest,
                phoneNumberUpdatedPersonalisation,
                String.valueOf(NotificationType.PHONE_NUMBER_UPDATED));
    }

    private void sendPasswordUpdatedNotification(NotifyRequest notifyRequest) {
        Map<String, Object> passwordUpdatedPersonalisation = new HashMap<>();
        passwordUpdatedPersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(
                notifyRequest,
                passwordUpdatedPersonalisation,
                String.valueOf(NotificationType.PASSWORD_UPDATED));
    }

    private void sendEmailNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        try {
            LOG.info("Sending {} email using Notify", notificationType);
            notificationService.sendEmail(
                    notifyRequest.getDestination(),
                    personalisation,
                    NotificationType.valueOf(notificationType));
            LOG.info(EMAIL_HAS_BEEN_SENT_USING_NOTIFY, notificationType);
        } catch (NotificationClientException e) {
            LOG.error(ERROR_SENDING_WITH_NOTIFY, e.getMessage());
        } catch (RuntimeException e) {
            LOG.error(UNEXPECTED_ERROR_SENDING_NOTIFICATION, notificationType, e.getMessage());
        }
    }

    private void sendTextNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        try {
            LOG.info("Sending {} text using Notify", notificationType);
            notificationService.sendText(
                    notifyRequest.getDestination(),
                    personalisation,
                    NotificationType.valueOf(notificationType));
            LOG.info(TEXT_HAS_BEEN_SENT_USING_NOTIFY, notificationType);
        } catch (NotificationClientException e) {
            LOG.error(ERROR_SENDING_WITH_NOTIFY, e.getMessage());
        } catch (RuntimeException e) {
            LOG.error(UNEXPECTED_ERROR_SENDING_NOTIFICATION, notificationType, e.getMessage());
        }
    }

    private String buildContactUsUrl() {
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getContactUsLinkRoute())
                .toString();
    }
}
