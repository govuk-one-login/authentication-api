package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotificationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(NotificationHandler.class);

    private final NotificationService notificationService;
    private final Json objectMapper = Json.jackson();
    private final AmazonS3 s3Client;
    private final ConfigurationService configurationService;

    public NotificationHandler(
            NotificationService notificationService,
            ConfigurationService configurationService,
            AmazonS3 s3Client) {
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
        this.notificationService = new NotificationService(client);
        this.s3Client =
                AmazonS3Client.builder().withRegion(configurationService.getAwsRegion()).build();
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "frontend-api::" + getClass().getSimpleName(),
                () -> notifcationRequestHandler(event, context));
    }

    public Void notifcationRequestHandler(SQSEvent event, Context context) {

        Map<String, Object> notifyPersonalisation = new HashMap<>();

        for (SQSMessage msg : event.getRecords()) {
            try {
                NotifyRequest notifyRequest =
                        objectMapper.readValue(msg.getBody(), NotifyRequest.class);
                try {
                    switch (notifyRequest.getNotificationType()) {
                        case ACCOUNT_CREATED_CONFIRMATION:
                            notifyPersonalisation.put(
                                    "contact-us-link", buildContactUsUrl("accountCreatedEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    notifyPersonalisation,
                                    ACCOUNT_CREATED_CONFIRMATION);
                            break;
                        case VERIFY_EMAIL:
                            notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                            notifyPersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            notifyPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("confirmEmailAddressEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    notifyPersonalisation,
                                    VERIFY_EMAIL);
                            break;
                        case VERIFY_PHONE_NUMBER:
                            notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(),
                                    notifyPersonalisation,
                                    VERIFY_PHONE_NUMBER);
                            break;
                        case MFA_SMS:
                            notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                            notificationService.sendText(
                                    notifyRequest.getDestination(), notifyPersonalisation, MFA_SMS);
                            break;
                        case RESET_PASSWORD:
                            notifyPersonalisation.put(
                                    "reset-password-link", notifyRequest.getCode());
                            notifyPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("passwordResetRequestEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    notifyPersonalisation,
                                    RESET_PASSWORD);
                            break;
                        case PASSWORD_RESET_CONFIRMATION:
                            Map<String, Object> passwordResetConfirmationPersonalisation =
                                    new HashMap<>();
                            passwordResetConfirmationPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("passwordResetConfirmationEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    passwordResetConfirmationPersonalisation,
                                    PASSWORD_RESET_CONFIRMATION);
                            break;
                        case RESET_PASSWORD_WITH_CODE:
                            notifyPersonalisation.put("validation-code", notifyRequest.getCode());
                            notifyPersonalisation.put(
                                    "email-address", notifyRequest.getDestination());
                            notifyPersonalisation.put(
                                    "contact-us-link",
                                    buildContactUsUrl("passwordResetRequestEmail"));
                            notificationService.sendEmail(
                                    notifyRequest.getDestination(),
                                    notifyPersonalisation,
                                    RESET_PASSWORD_WITH_CODE);
                            break;
                    }
                    writeTestClientOtpToS3(notifyRequest.getCode(), notifyRequest.getDestination());
                } catch (NotificationClientException e) {
                    LOG.error(
                            "Error sending with Notify using NotificationType: {}",
                            notifyRequest.getNotificationType());
                    throw new RuntimeException(
                            String.format(
                                    "Error sending with Notify using NotificationType: %s",
                                    notifyRequest.getNotificationType()),
                            e);
                }
            } catch (JsonException e) {
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

    private void writeTestClientOtpToS3(String otp, String destination) {
        Boolean isNotifyTestNumber =
                configurationService
                        .getNotifyTestPhoneNumber()
                        .map(t -> t.equals(destination))
                        .orElse(false);
        if (isNotifyTestNumber) {
            LOG.info("Notify Test Number used in request. Writing to S3 bucket");
            String key = configurationService.getNotifyTestPhoneNumber().get();
            String bucketName = configurationService.getSmoketestBucketName();
            try {
                s3Client.putObject(bucketName, key, otp);
            } catch (Exception e) {
                LOG.error("Exception thrown when writing to S3 bucket");
            }
        }
    }
}
