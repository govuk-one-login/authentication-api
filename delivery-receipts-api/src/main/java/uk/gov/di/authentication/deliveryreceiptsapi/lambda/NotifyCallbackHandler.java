package uk.gov.di.authentication.deliveryreceiptsapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class NotifyCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private final ConfigurationService configurationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(NotifyCallbackHandler.class);

    public NotifyCallbackHandler(
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
    }

    public NotifyCallbackHandler(ConfigurationService configurationService) {
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.configurationService = configurationService;
    }

    public NotifyCallbackHandler() {
        this(ConfigurationService.getInstance());
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
        LOG.info("Received request");
        validateBearerToken(input.getHeaders());
        NotifyDeliveryReceipt deliveryReceipt;
        try {
            deliveryReceipt = objectMapper.readValue(input.getBody(), NotifyDeliveryReceipt.class);
            if (deliveryReceipt.getNotificationType().equals("sms")) {
                LOG.info("Sms delivery receipt received");
                var countryCode = getCountryCodeFromNumber(deliveryReceipt.getTo());
                LOG.info(
                        "SmsSent, NotifyStatus: {}, CountryCode: {}",
                        deliveryReceipt.getStatus(),
                        countryCode);
                var templateId = deliveryReceipt.getTemplateId();
                LOG.info("Template ID received in delivery receipt: {}", templateId);
                var templateName = getTemplateName(templateId);
                cloudwatchMetricsService.incrementCounter(
                        "SmsSent",
                        Map.of(
                                "SmsType",
                                templateName,
                                "CountryCode",
                                String.valueOf(countryCode),
                                "Environment",
                                configurationService.getEnvironment(),
                                "NotifyStatus",
                                deliveryReceipt.getStatus()));
                LOG.info("SMS callback request processed");
            } else if (deliveryReceipt.getNotificationType().equals("email")) {
                LOG.info("Email delivery receipt received");
                var templateId = deliveryReceipt.getTemplateId();
                LOG.info("Template ID received in delivery receipt: {}", templateId);
                var templateName = getTemplateName(templateId);
                cloudwatchMetricsService.incrementCounter(
                        "EmailSent",
                        Map.of(
                                "EmailName",
                                templateName,
                                "Environment",
                                configurationService.getEnvironment(),
                                "NotifyStatus",
                                deliveryReceipt.getStatus()));
                LOG.info("Email callback request processed");
            }
        } catch (JsonException e) {
            LOG.error("Unable to parse Notify Delivery Receipt");
            throw new RuntimeException("Unable to parse Notify Delivery Receipt");
        }
        return generateEmptySuccessApiGatewayResponse();
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
