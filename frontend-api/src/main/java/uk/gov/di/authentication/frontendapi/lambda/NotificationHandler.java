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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

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
        attachTraceId();

        if (event != null && event.getRecords() != null) {
            LOG.info("Processing Notification batch size: {}", event.getRecords().size());
        }
        for (SQSMessage msg : event.getRecords()) {
            LOG.info("Processing Notification message with id: {}", msg.getMessageId());
            var request = parseNotifyRequest(msg);
            LOG.info(
                    "Processing NotifyRequest with reference: {}",
                    request.getUniqueNotificationReference());
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

    private Map<String, Object> getPersonalisation(NotifyRequest notifyRequest) {
        return switch (notifyRequest.getNotificationType()) {
            case ACCOUNT_CREATED_CONFIRMATION -> Map.of(
                    "contact-us-link",
                    buildContactUsUrl(),
                    "gov-uk-accounts-url",
                    configurationService.getGovUKAccountsURL().toString());
            case VERIFY_EMAIL, RESET_PASSWORD_WITH_CODE -> Map.of(
                    "validation-code", notifyRequest.getCode(),
                    "email-address", notifyRequest.getDestination(),
                    "contact-us-link", buildContactUsUrl());
            case VERIFY_PHONE_NUMBER, MFA_SMS -> Map.of("validation-code", notifyRequest.getCode());
            case PASSWORD_RESET_CONFIRMATION,
                    CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION,
                    PASSWORD_RESET_CONFIRMATION_SMS -> Map.of(
                    "contact-us-link", buildContactUsUrl());
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> Map.of(
                    "validation-code",
                    notifyRequest.getCode(),
                    "email-address",
                    notifyRequest.getDestination());
            case TERMS_AND_CONDITIONS_BULK_EMAIL -> Collections.emptyMap();
        };
    }

    private void sendNotifyMessage(NotifyRequest request) {

        if (request.getNotificationType() == TERMS_AND_CONDITIONS_BULK_EMAIL) {
            LOG.info("Not dispatching terms and conditions bulk email.");
            return;
        }

        try {
            var personalisation = getPersonalisation(request);
            var reference =
                    String.format(
                            "%s/%s",
                            request.getUniqueNotificationReference(), request.getClientSessionId());

            if (request.getNotificationType().isEmail()) {
                notificationService.sendEmail(
                        request.getDestination(),
                        personalisation,
                        request.getNotificationType(),
                        reference);
            } else {
                notificationService.sendText(
                        request.getDestination(),
                        personalisation,
                        request.getNotificationType(),
                        reference);
            }
            writeTestClientOtpToS3(
                    request.getNotificationType(), request.getCode(), request.getDestination());
        } catch (NotificationClientException e) {
            LOG.error(
                    "Error sending with Notify using NotificationType: {}",
                    request.getNotificationType());

            if (isPhoneNotification(request.getNotificationType())) {
                String countryCode =
                        PhoneNumberHelper.maybeGetCountry(request.getDestination())
                                .orElse("unable to parse country");
                throw new RuntimeException(
                        String.format(
                                "Error sending Notify SMS with NotificationType: %s and country code: %s",
                                request.getNotificationType(), countryCode),
                        e);
            }

            throw new RuntimeException(
                    String.format(
                            "Error sending Notify email with NotificationType: %s",
                            request.getNotificationType()),
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
