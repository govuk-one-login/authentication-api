package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.CONTACT_US_LINK_PERSONALISATION;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.EMAIL_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.ERROR_SENDING_WITH_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.ERROR_WHEN_MAPPING_MESSAGE_FROM_QUEUE_TO_A_NOTIFY_REQUEST;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.TEXT_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.UNEXPECTED_ERROR_SENDING_NOTIFICATION;
import static uk.gov.di.authentication.entity.Application.ONE_LOGIN_HOME;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);
    public static final String VALIDATION_CODE_PERSONALISATION = "validation-code";
    public static final String EMAIL_ADDRESS_PERSONALISATION = "email-address";
    public static final String EXCEPTION_THROWN_WHEN_WRITING_TO_S_3_BUCKET =
            "Exception thrown when writing to S3 bucket: {}";
    private final NotificationService notificationService;
    private final Json objectMapper = SerializationService.getInstance();
    private final ConfigurationService configurationService;
    private final S3Client s3Client;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public NotificationHandler(
            NotificationService notificationService,
            ConfigurationService configService,
            S3Client s3Client,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.notificationService = notificationService;
        this.configurationService = configService;
        this.s3Client = s3Client;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
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
        this.s3Client =
                S3Client.builder().region(Region.of(configurationService.getAwsRegion())).build();
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> notificationRequestHandler(event));
        return null;
    }

    public void notificationRequestHandler(SQSEvent event) {
        attachTraceId();
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
            case BACKUP_METHOD_ADDED -> sendBackupAddedNotification(notifyRequest);
            case BACKUP_METHOD_REMOVED -> sendBackupRemovedNotification(notifyRequest);
            case CHANGED_AUTHENTICATOR_APP -> sendChangedAuthenticatorAppNotification(
                    notifyRequest);
            case CHANGED_DEFAULT_MFA -> sendChangedDefaultMFANotification(notifyRequest);
            case SWITCHED_MFA_METHODS -> sendSwitchedMFAMethodsNotification(notifyRequest);
        }
    }

    private void sendVerifyEmailNotification(NotifyRequest notifyRequest) {
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put(VALIDATION_CODE_PERSONALISATION, notifyRequest.getCode());
        emailPersonalisation.put(EMAIL_ADDRESS_PERSONALISATION, notifyRequest.getDestination());
        emailPersonalisation.put(CONTACT_US_LINK_PERSONALISATION, buildContactUsUrl());
        sendEmailNotification(notifyRequest, emailPersonalisation, String.valueOf(VERIFY_EMAIL));
    }

    private void sendVerifyPhoneNotification(NotifyRequest notifyRequest) {
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put(VALIDATION_CODE_PERSONALISATION, notifyRequest.getCode());
        sendTextNotification(
                notifyRequest, phonePersonalisation, String.valueOf(VERIFY_PHONE_NUMBER));
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

    private void sendBackupAddedNotification(NotifyRequest notifyRequest) {
        sendEmailNotification(
                notifyRequest,
                Collections.emptyMap(),
                String.valueOf(NotificationType.BACKUP_METHOD_ADDED));
    }

    private void sendBackupRemovedNotification(NotifyRequest notifyRequest) {
        sendEmailNotification(
                notifyRequest,
                Collections.emptyMap(),
                String.valueOf(NotificationType.BACKUP_METHOD_REMOVED));
    }

    private void sendChangedAuthenticatorAppNotification(NotifyRequest notifyRequest) {
        sendEmailNotification(
                notifyRequest,
                Collections.emptyMap(),
                String.valueOf(NotificationType.CHANGED_AUTHENTICATOR_APP));
    }

    private void sendChangedDefaultMFANotification(NotifyRequest notifyRequest) {
        sendEmailNotification(
                notifyRequest,
                Collections.emptyMap(),
                String.valueOf(NotificationType.CHANGED_DEFAULT_MFA));
    }

    private void sendSwitchedMFAMethodsNotification(NotifyRequest notifyRequest) {
        sendEmailNotification(
                notifyRequest,
                Collections.emptyMap(),
                String.valueOf(NotificationType.SWITCHED_MFA_METHODS));
    }

    private void sendEmailNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        sendNotification(
                notifyRequest,
                personalisation,
                notificationType,
                (destination, notificationReference, per, type) -> {
                    try {
                        notificationService.sendEmail(
                                destination,
                                per,
                                NotificationType.valueOf(type),
                                notificationReference);
                        LOG.info(EMAIL_HAS_BEEN_SENT_USING_NOTIFY, notificationType);
                        cloudwatchMetricsService.emitMetricForNotification(
                                notifyRequest.getNotificationType(),
                                destination,
                                false,
                                ONE_LOGIN_HOME);
                    } catch (NotificationClientException e) {
                        LOG.error(
                                ERROR_SENDING_WITH_NOTIFY,
                                notificationType,
                                notificationReference,
                                e.getMessage());
                        cloudwatchMetricsService.emitMetricForNotificationError(
                                notifyRequest.getNotificationType(),
                                destination,
                                false,
                                ONE_LOGIN_HOME,
                                e);
                    } catch (RuntimeException e) {
                        LOG.error(
                                UNEXPECTED_ERROR_SENDING_NOTIFICATION,
                                notificationType,
                                notificationReference,
                                e.getMessage());
                    }
                });
    }

    private void sendTextNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType) {
        sendNotification(
                notifyRequest,
                personalisation,
                notificationType,
                (destination, notificationReference, per, type) -> {
                    try {
                        notificationService.sendText(
                                destination,
                                per,
                                NotificationType.valueOf(type),
                                notificationReference);
                        LOG.info(TEXT_HAS_BEEN_SENT_USING_NOTIFY, notificationType);
                        cloudwatchMetricsService.emitMetricForNotification(
                                notifyRequest.getNotificationType(),
                                destination,
                                false,
                                ONE_LOGIN_HOME);
                    } catch (NotificationClientException e) {
                        LOG.error(
                                ERROR_SENDING_WITH_NOTIFY,
                                notificationType,
                                notificationReference,
                                e.getMessage());
                        cloudwatchMetricsService.emitMetricForNotificationError(
                                notifyRequest.getNotificationType(),
                                destination,
                                false,
                                ONE_LOGIN_HOME,
                                e);
                    } catch (RuntimeException e) {
                        LOG.error(
                                UNEXPECTED_ERROR_SENDING_NOTIFICATION,
                                notificationType,
                                notificationReference,
                                e.getMessage());
                    }
                });
    }

    @FunctionalInterface
    private interface NotificationSender {
        void send(
                String destination,
                String notificationReference,
                Map<String, Object> personalisation,
                String notificationType);
    }

    private void sendNotification(
            NotifyRequest notifyRequest,
            Map<String, Object> personalisation,
            String notificationType,
            NotificationSender sender) {
        var isDestinationOnTestDestinationsList =
                configurationService
                        .getNotifyTestDestinations()
                        .contains(notifyRequest.getDestination());

        var isTestUserThatShouldNotInvokeNotify =
                notifyRequest.isTestClient() && isDestinationOnTestDestinationsList;

        if (isTestUserThatShouldNotInvokeNotify) {
            LOG.info("Test client detected writing code to S3");
            writeTestClientOtpToS3(
                    notifyRequest.getNotificationType(),
                    notifyRequest.getCode(),
                    notifyRequest.getEmail());
        } else {
            sender.send(
                    notifyRequest.getDestination(),
                    notifyRequest.getUniqueNotificationReference(),
                    personalisation,
                    notificationType);
        }
    }

    private String buildContactUsUrl() {
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getContactUsLinkRoute())
                .toString();
    }

    void writeTestClientOtpToS3(NotificationType notificationType, String otp, String email) {
        var isOTPNotificationType =
                List.of(
                                VERIFY_EMAIL,
                                MFA_SMS,
                                VERIFY_PHONE_NUMBER,
                                RESET_PASSWORD_WITH_CODE,
                                VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                        .contains(notificationType);

        if (isOTPNotificationType) {
            LOG.info(
                    LogMessageTemplates.NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET,
                    notificationType);
            String bucketName = configurationService.getAccountManagementNotifyBucketDestination();

            try {
                var putObjectRequest =
                        PutObjectRequest.builder().bucket(bucketName).key(email).build();
                s3Client.putObject(putObjectRequest, RequestBody.fromString(otp));
                if ("integration".equals(configurationService.getEnvironment())) {
                    LOG.info(LogMessageTemplates.WRITING_OTP_TO_S_3_BUCKET, otp);
                }
            } catch (Exception e) {
                LOG.error(EXCEPTION_THROWN_WHEN_WRITING_TO_S_3_BUCKET, e.getMessage(), e);
            }
        } else {
            LOG.info(
                    LogMessageTemplates.NOT_WRITING_TO_BUCKET_AS_NOT_OTP_NOTIFICATION,
                    notificationType);
        }
    }
}
