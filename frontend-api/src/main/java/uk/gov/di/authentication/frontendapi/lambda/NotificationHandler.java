package uk.gov.di.authentication.frontendapi.lambda;

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
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);

    private final NotificationService notificationService;
    private final Json objectMapper = SerializationService.getInstance();
    private final S3Client s3Client;
    private final ConfigurationService configurationService;

    public NotificationHandler(
            NotificationService notificationService,
            ConfigurationService configurationService,
            S3Client s3Client) {
        this.notificationService = notificationService;
        this.configurationService = configurationService;
        this.s3Client = s3Client;
    }

    public NotificationHandler() {
        this(ConfigurationService.getInstance());
    }

    public NotificationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        NotificationClient client =
                configurationService
                        .getNotifyApiUrl()
                        .map(
                                url ->
                                        new NotificationClient(
                                                configurationService.getNotifyApiKey(), url))
                        .orElse(new NotificationClient(configurationService.getNotifyApiKey()));
        this.notificationService = new NotificationService(client, configurationService);
        this.s3Client =
                S3Client.builder().region(Region.of(configurationService.getAwsRegion())).build();
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "frontend-api::" + getClass().getSimpleName(),
                () -> notificationRequestHandler(event, context));
    }

    public Void notificationRequestHandler(SQSEvent event, Context context) {

        if (event != null && event.getRecords() != null) {
            LOG.info("Processing Notification batch size: {}", event.getRecords().size());
        }
        for (SQSMessage msg : event.getRecords()) {
            LOG.info("Processing Notification message with id: {}", msg.getMessageId());
            var request = parseNotifyRequest(msg);
            sendNotifyMessage(request);
        }
        return null;
    }

    private NotifyRequest parseNotifyRequest(SQSMessage msg) {
        try {
            return objectMapper.readValue(msg.getBody(), NotifyRequest.class);
        } catch (JsonException e) {
            LOG.error("Error when mapping message from queue to a NotifyRequest");
            throw new RuntimeException("Error when mapping message from queue to a NotifyRequest");
        }
    }

    private void sendNotifyMessage(NotifyRequest notifyRequest) {
        try {

            switch (notifyRequest.getNotificationType()) {
                case ACCOUNT_CREATED_CONFIRMATION -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("contact-us-link", buildContactUsUrl());
                    notifyPersonalisation.put(
                            "gov-uk-accounts-url",
                            configurationService.getGovUKAccountsURL().toString());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            ACCOUNT_CREATED_CONFIRMATION,
                            notifyRequest.getLanguage());
                }
                case VERIFY_EMAIL -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                    notifyPersonalisation.put("email-address", notifyRequest.getDestination());
                    notifyPersonalisation.put("contact-us-link", buildContactUsUrl());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            VERIFY_EMAIL,
                            notifyRequest.getLanguage());
                }
                case VERIFY_PHONE_NUMBER -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                    notificationService.sendText(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            VERIFY_PHONE_NUMBER,
                            notifyRequest.getLanguage());
                }
                case MFA_SMS -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                    notificationService.sendText(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            MFA_SMS,
                            notifyRequest.getLanguage());
                }
                case PASSWORD_RESET_CONFIRMATION -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("contact-us-link", buildContactUsUrl());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            PASSWORD_RESET_CONFIRMATION,
                            notifyRequest.getLanguage());
                }
                case PASSWORD_RESET_CONFIRMATION_SMS -> {
                    Map<String, Object> notifyPersonalisation =
                            Map.of("contact-us-link", buildContactUsUrl());
                    notificationService.sendText(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            PASSWORD_RESET_CONFIRMATION_SMS,
                            notifyRequest.getLanguage());
                }
                case RESET_PASSWORD_WITH_CODE -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                    notifyPersonalisation.put("email-address", notifyRequest.getDestination());
                    notifyPersonalisation.put("contact-us-link", buildContactUsUrl());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            RESET_PASSWORD_WITH_CODE,
                            notifyRequest.getLanguage());
                }
                case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                    notifyPersonalisation.put("email-address", notifyRequest.getDestination());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                            notifyRequest.getLanguage());
                }
                case CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION -> {
                    Map<String, Object> notifyPersonalisation = new HashMap<>();
                    notifyPersonalisation.put("contact-us-link", buildContactUsUrl());
                    notificationService.sendEmail(
                            notifyRequest.getDestination(),
                            notifyPersonalisation,
                            CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION,
                            notifyRequest.getLanguage());
                }
            }
            writeTestClientOtpToS3(
                    notifyRequest.getNotificationType(),
                    notifyRequest.getCode(),
                    notifyRequest.getDestination());
        } catch (NotificationClientException e) {
            LOG.error(
                    "Error sending with Notify using NotificationType: {}",
                    notifyRequest.getNotificationType());

            if (isPhoneNotification(notifyRequest.getNotificationType())) {
                String countryCode =
                        PhoneNumberHelper.maybeGetCountry(notifyRequest.getDestination())
                                .orElse("unable to parse country");
                throw new RuntimeException(
                        String.format(
                                "Error sending Notify SMS with NotificationType: %s and country code: %s",
                                notifyRequest.getNotificationType(), countryCode),
                        e);
            }

            throw new RuntimeException(
                    String.format(
                            "Error sending Notify email with NotificationType: %s",
                            notifyRequest.getNotificationType()),
                    e);
        }
    }

    private boolean isPhoneNotification(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_PHONE_NUMBER:
            case MFA_SMS:
            case PASSWORD_RESET_CONFIRMATION_SMS:
                return true;
            default:
                return false;
        }
    }

    private String buildContactUsUrl() {
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getContactUsLinkRoute())
                .toString();
    }

    void writeTestClientOtpToS3(NotificationType notificationType, String otp, String destination) {
        var isNotifyDestination =
                configurationService.getNotifyTestDestinations().contains(destination);
        var isOTPNotificationType =
                List.of(
                                VERIFY_EMAIL,
                                MFA_SMS,
                                VERIFY_PHONE_NUMBER,
                                RESET_PASSWORD_WITH_CODE,
                                VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                        .contains(notificationType);
        if (isNotifyDestination && isOTPNotificationType) {
            LOG.info(
                    "Notify Test Destination used in request. Writing to S3 bucket for notification type {}",
                    notificationType);
            String bucketName = configurationService.getSmoketestBucketName();
            try {
                var putObjectRequest =
                        PutObjectRequest.builder().bucket(bucketName).key(destination).build();
                s3Client.putObject(putObjectRequest, RequestBody.fromString(otp));
                if ("integration".equals(configurationService.getEnvironment())) {
                    LOG.info("Writing OTP to S3 bucket: {}", otp);
                }
            } catch (Exception e) {
                LOG.error(
                        "Exception thrown when writing to S3 bucket: {}",
                        Arrays.toString(e.getStackTrace()));
            }
        }
    }
}
