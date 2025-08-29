package uk.gov.di.authentication.deliveryreceiptsapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyReference;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SystemService;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class NotifyCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String AUTHORIZATION_HEADER = "Authorization";

    // region Logging
    private static final String NOTIFICATION_ID = "notificationId";
    private static final String UNIQUE_NOTIFICATION_REFERENCE = "uniqueNotificationReference";
    private static final String JOURNEY_ID = "journeyId";
    private static final Logger LOG = LogManager.getLogger(NotifyCallbackHandler.class);
    // endregion

    private final ConfigurationService configurationService;
    private DynamoService dynamoService = null;
    private BulkEmailUsersService bulkEmailUsersService = null;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final Json objectMapper = SerializationService.getInstance();

    public NotifyCallbackHandler(
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            BulkEmailUsersService bulkEmailUsersService) {
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        if (configurationService.isBulkUserEmailEnabled()) {
            this.dynamoService = dynamoService;
            this.bulkEmailUsersService = bulkEmailUsersService;
        }
    }

    public NotifyCallbackHandler(ConfigurationService configurationService) {
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.configurationService = configurationService;
        if (configurationService.isBulkUserEmailEnabled()) {
            this.dynamoService = new DynamoService(configurationService);
            this.bulkEmailUsersService = new BulkEmailUsersService(configurationService);
        }
    }

    public NotifyCallbackHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "delivery-receipts-api::" + getClass().getSimpleName(),
                () -> notifyCallbackRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent notifyCallbackRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        attachTraceId();
        LOG.info("Received request");
        validateBearerToken(input.getHeaders());
        NotifyDeliveryReceipt deliveryReceipt;
        try {
            deliveryReceipt = objectMapper.readValue(input.getBody(), NotifyDeliveryReceipt.class);
            var notifyReference = new NotifyReference(deliveryReceipt.reference());

            ThreadContext.clearMap();
            ThreadContext.put(NOTIFICATION_ID, deliveryReceipt.id());
            ThreadContext.put(
                    UNIQUE_NOTIFICATION_REFERENCE,
                    notifyReference.getUniqueNotificationReference());
            ThreadContext.put(JOURNEY_ID, notifyReference.getClientSessionId());

            if (deliveryReceipt.notificationType().equals("sms")) {
                LOG.info("Sms delivery receipt received");
                var countryCode = getCountryCodeFromNumber(deliveryReceipt.to());
                LOG.info(
                        "SmsSent, NotifyStatus: {}, CountryCode: {}",
                        deliveryReceipt.status(),
                        countryCode);
                var templateId = deliveryReceipt.templateId();
                LOG.info("Template ID received in delivery receipt: {}", templateId);
                var templateName = getTemplateName(templateId);
                var smsDestinationType = countryCode == 44 ? "DOMESTIC" : "INTERNATIONAL";
                var additionalMetricsContext =
                        Map.of(
                                "SmsType",
                                templateName,
                                "CountryCode",
                                String.valueOf(countryCode),
                                "SmsDestinationType",
                                smsDestinationType);
                incrementCounters("SmsSent", additionalMetricsContext, deliveryReceipt);
                LOG.info("SMS callback request processed");
            } else if (deliveryReceipt.notificationType().equals("email")) {
                LOG.info("Email delivery receipt received");
                var templateId = deliveryReceipt.templateId();
                LOG.info("Template ID received in delivery receipt: {}", templateId);
                var templateName = getTemplateName(templateId);
                incrementCounters("EmailSent", Map.of("EmailName", templateName), deliveryReceipt);
                if (configurationService.isBulkUserEmailEnabled()
                        && templateName.equals(
                                TERMS_AND_CONDITIONS_BULK_EMAIL.getTemplateAlias())) {
                    LOG.info("Updating bulk email table for delivery receipt");
                    var maybeProfile =
                            dynamoService.getUserProfileByEmailMaybe(deliveryReceipt.to());
                    if (maybeProfile.isPresent()) {
                        bulkEmailUsersService.updateDeliveryReceiptStatus(
                                maybeProfile.get().getSubjectID(), deliveryReceipt.status());
                    } else {
                        LOG.info(
                                "No profile found for email in delivery receipt: not updating bulk email users table");
                    }
                }
                LOG.info("Email callback request processed");
            }
        } catch (JsonException e) {
            LOG.error("Unable to parse Notify Delivery Receipt");
            ThreadContext.clearMap();
            throw new RuntimeException("Unable to parse Notify Delivery Receipt");
        }
        ThreadContext.clearMap();
        return generateEmptySuccessApiGatewayResponse();
    }

    private void incrementCounters(
            String sentMetricName,
            Map<String, String> additionalContext,
            NotifyDeliveryReceipt deliveryReceipt) {
        var sentMetricsMap = new HashMap<String, String>();
        sentMetricsMap.put("Environment", configurationService.getEnvironment());
        sentMetricsMap.put("NotifyStatus", deliveryReceipt.status());
        sentMetricsMap.putAll(additionalContext);

        cloudwatchMetricsService.incrementCounter(sentMetricName, sentMetricsMap);

        if (deliveryReceipt.status().equals("delivered")) {
            sendDurationMetrics(deliveryReceipt);
        }
    }

    private void sendDurationMetrics(NotifyDeliveryReceipt deliveryReceipt) {
        if (Objects.isNull(deliveryReceipt.completedAt())
                || Objects.isNull(deliveryReceipt.createdAt())) {
            return;
        }
        try {
            var completedAt = Instant.parse(deliveryReceipt.completedAt());
            var createdAt = Instant.parse(deliveryReceipt.createdAt());
            double duration = Duration.between(createdAt, completedAt).toMillis();
            var metricsContext =
                    Map.ofEntries(
                            Map.entry("Environment", configurationService.getEnvironment()),
                            Map.entry("NotificationType", deliveryReceipt.notificationType()));
            cloudwatchMetricsService.putEmbeddedValue(
                    "NotifyDeliveryDuration", duration, metricsContext);
        } catch (DateTimeParseException e) {
            LOG.warn(
                    format(
                            "Invalid date time when parsing duration metrics for delivery receipts %s",
                            e.getMessage()));
        }
    }

    private void validateBearerToken(Map<String, String> headers) {
        var notifyCallbackBearerToken = configurationService.getNotifyCallbackBearerToken();
        if (Objects.isNull(headers.get(AUTHORIZATION_HEADER))
                || !headers.get(AUTHORIZATION_HEADER).startsWith("Bearer ")) {
            LOG.error("No bearer token in request");
            throw new RuntimeException("No bearer token in request");
        }
        var token = headers.get(AUTHORIZATION_HEADER).substring(7);
        if (!token.equals(notifyCallbackBearerToken)) {
            LOG.error("Invalid bearer token in request");
            throw new RuntimeException("Invalid bearer token in request");
        }
    }

    private int getCountryCodeFromNumber(String number) {
        var phoneUtil = PhoneNumberUtil.getInstance();
        try {
            return phoneUtil.parse(number, "GB").getCountryCode();
        } catch (NumberParseException e) {
            LOG.error("Unable to parse number");
            throw new RuntimeException("Unable to parse number");
        }
    }

    private String getTemplateName(String templateID) {
        return configurationService
                .getNotificationTypeFromTemplateId(templateID)
                .map(DeliveryReceiptsNotificationType::getTemplateAlias)
                .orElseThrow(
                        () -> {
                            LOG.error("No template found with template ID: {}", templateID);
                            throw new RuntimeException("No template found with template ID");
                        });
    }
}
