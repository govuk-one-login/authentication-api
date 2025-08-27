package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClientException;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.entity.Application.AUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class NotificationHandlerTest {

    private static final String BUCKET_NAME = "test-s3-bucket";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-us";
    private static final URI GOV_UK_ACCOUNTS_URL = URI.create("gov-uk-accounts-url");
    private static final String TEST_UNIQUE_NOTIFICATION_REFERENCE =
            "known-unique-notification-reference";
    private static final String TEST_MESSAGE_ID = "test-message-id";
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final S3Client s3Client = mock(S3Client.class);
    private NotificationHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private static final String EXPECTED_REFERENCE =
            String.format(
                    "%s/%s",
                    TEST_UNIQUE_NOTIFICATION_REFERENCE, CommonTestVariables.CLIENT_SESSION_ID);

    @BeforeEach
    void setUp() {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(UK_MOBILE_NUMBER));
        when(configService.getSmoketestBucketName()).thenReturn(BUCKET_NAME);
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        when(configService.getGovUKAccountsURL()).thenReturn(GOV_UK_ACCOUNTS_URL);
        when(configService.getEnvironment()).thenReturn("unit-test");
        handler =
                new NotificationHandler(
                        notificationService, configService, s3Client, cloudwatchMetricsService);
    }

    @Test
    void shouldSuccessfullyProcessEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, VERIFY_EMAIL, "654321");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(EMAIL, personalisation, VERIFY_EMAIL, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(VERIFY_EMAIL, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationEmailFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, PASSWORD_RESET_CONFIRMATION, null);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(EMAIL, personalisation, PASSWORD_RESET_CONFIRMATION, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        PASSWORD_RESET_CONFIRMATION, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationSMSFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        var sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, PASSWORD_RESET_CONFIRMATION_SMS, null);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = Map.of("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendText(
                        UK_MOBILE_NUMBER,
                        personalisation,
                        PASSWORD_RESET_CONFIRMATION_SMS,
                        EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        PASSWORD_RESET_CONFIRMATION_SMS, UK_MOBILE_NUMBER, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessAccountCreatedConfirmationFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        String baseUrl = "http://account-management";
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        var govUKAccountsUrl = URI.create("https://www.gov.uk/account");
        when(configService.getAccountManagementURI()).thenReturn(baseUrl);
        when(configService.getGovUKAccountsURL()).thenReturn(govUKAccountsUrl);

        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, ACCOUNT_CREATED_CONFIRMATION, null);

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);
        personalisation.put("gov-uk-accounts-url", govUKAccountsUrl.toString());

        verify(notificationService)
                .sendEmail(
                        EMAIL, personalisation, ACCOUNT_CREATED_CONFIRMATION, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        ACCOUNT_CREATED_CONFIRMATION, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        UK_MOBILE_NUMBER, personalisation, VERIFY_PHONE_NUMBER, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        VERIFY_PHONE_NUMBER, UK_MOBILE_NUMBER, true, AUTHENTICATION);
    }

    @Test
    void shouldNotSendAnythingWhenATermsAndConditionsBulkEmail() throws Json.JsonException {
        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, TERMS_AND_CONDITIONS_BULK_EMAIL, "");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        verifyNoInteractions(notificationService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldThrowExceptionIfUnableToProcessMessageFromQueue() {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody("");
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error when mapping message from queue to a NotifyRequest", exception.getMessage());

        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturnBatchFailureIfNotifyIsUnableToSendEmail()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, VERIFY_EMAIL, "654321");
        var notificationClientException = new NotificationClientException("test-exception-message");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);
        Mockito.doThrow(notificationClientException)
                .when(notificationService)
                .sendEmail(EMAIL, personalisation, VERIFY_EMAIL, EXPECTED_REFERENCE);

        var response = handler.handleRequest(sqsEvent, context);

        assertEquals(1, response.getBatchItemFailures().size());
        assertEquals(TEST_MESSAGE_ID, response.getBatchItemFailures().get(0).getItemIdentifier());

        verify(cloudwatchMetricsService)
                .emitMetricForNotificationError(
                        VERIFY_EMAIL, EMAIL, false, AUTHENTICATION, notificationClientException);
    }

    @Test
    void shouldReturnBatchFailureIfNotifyIsUnableToSendText()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        var notificationClientException = new NotificationClientException("test-exception-message");

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        Mockito.doThrow(notificationClientException)
                .when(notificationService)
                .sendText(
                        UK_MOBILE_NUMBER, personalisation, VERIFY_PHONE_NUMBER, EXPECTED_REFERENCE);

        var response = handler.handleRequest(sqsEvent, context);

        assertEquals(1, response.getBatchItemFailures().size());
        assertEquals(TEST_MESSAGE_ID, response.getBatchItemFailures().get(0).getItemIdentifier());

        verify(cloudwatchMetricsService)
                .emitMetricForNotificationError(
                        VERIFY_PHONE_NUMBER,
                        UK_MOBILE_NUMBER,
                        true,
                        AUTHENTICATION,
                        notificationClientException);
    }

    @Test
    void shouldStillProcessOtherMessagesIfNotifyIsUnableToSendOne()
            throws Json.JsonException, NotificationClientException {
        var badCode = "123456";
        var goodCode = "456789";

        var goodMessage1 = notifyRequestMessage(EMAIL, VERIFY_EMAIL, goodCode, "good-message-1");
        var badMessage = notifyRequestMessage(EMAIL, VERIFY_EMAIL, badCode, "bad-message");
        var goodMessage2 = notifyRequestMessage(EMAIL, VERIFY_EMAIL, goodCode, "good-message-2");

        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(List.of(goodMessage1, badMessage, goodMessage2));

        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        var badPersonalisation =
                Map.<String, Object>of(
                        "validation-code", badCode,
                        "email-address", EMAIL,
                        "contact-us-link", contactUsLinkUrl);

        var goodPersonalisation =
                Map.<String, Object>of(
                        "validation-code", goodCode,
                        "email-address", EMAIL,
                        "contact-us-link", contactUsLinkUrl);

        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(EMAIL, badPersonalisation, VERIFY_EMAIL, EXPECTED_REFERENCE);

        var response = handler.handleRequest(sqsEvent, context);

        // Good messages are sent
        verify(notificationService, times(2))
                .sendEmail(EMAIL, goodPersonalisation, VERIFY_EMAIL, EXPECTED_REFERENCE);

        // Bad message is included in a batch failure
        assertEquals(1, response.getBatchItemFailures().size());
        assertEquals(
                badMessage.getMessageId(),
                response.getBatchItemFailures().get(0).getItemIdentifier());
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        UK_MOBILE_NUMBER, personalisation, VERIFY_PHONE_NUMBER, EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(UK_MOBILE_NUMBER).build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, MFA_SMS, "654321");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(UK_MOBILE_NUMBER, personalisation, MFA_SMS, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(MFA_SMS, UK_MOBILE_NUMBER, true, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, MFA_SMS, "654321");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(UK_MOBILE_NUMBER, personalisation, MFA_SMS, EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(UK_MOBILE_NUMBER).build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(MFA_SMS, UK_MOBILE_NUMBER, true, AUTHENTICATION);
    }

    @Test
    void
            shouldSuccessfullyProcessAccountConfirmationRequestFromSQSQueueAndNotWriteOTPToS3WhenTestClient()
                    throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, ACCOUNT_CREATED_CONFIRMATION, null);

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", buildContactUsUrl());
        personalisation.put("gov-uk-accounts-url", GOV_UK_ACCOUNTS_URL.toString());

        verify(notificationService)
                .sendEmail(
                        EMAIL, personalisation, ACCOUNT_CREATED_CONFIRMATION, EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(UK_MOBILE_NUMBER).build();
        verify(s3Client, times(0)).putObject(eq(putObjectRequest), any(RequestBody.class));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        ACCOUNT_CREATED_CONFIRMATION, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessPasswordResetWithCodeMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent = notifyRequestEvent(EMAIL, RESET_PASSWORD_WITH_CODE, "654321");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(EMAIL, personalisation, RESET_PASSWORD_WITH_CODE, EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(RESET_PASSWORD_WITH_CODE, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldSuccessfullyProcessVerifyChangeHowGetSecurityCodesMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "654321");

        var response = handler.handleRequest(sqsEvent, context);

        assertTrue(response.getBatchItemFailures().isEmpty());

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", EMAIL);

        verify(notificationService)
                .sendEmail(
                        EMAIL,
                        personalisation,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        EXPECTED_REFERENCE);
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES, EMAIL, false, AUTHENTICATION);
    }

    @Test
    void shouldEmitSmsLimitExceededMetricWhen429ResponseReceived()
            throws Json.JsonException, NotificationClientException {
        NotificationClientException exception = mock(NotificationClientException.class);
        when(exception.getHttpResult()).thenReturn(429);

        Mockito.doThrow(exception).when(notificationService).sendText(any(), any(), any(), any());

        SQSEvent sqsEvent = notifyRequestEvent(UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "123456");

        var response = handler.handleRequest(sqsEvent, context);

        assertEquals(1, response.getBatchItemFailures().size());

        verify(cloudwatchMetricsService)
                .emitSmsLimitExceededMetric(
                        VERIFY_PHONE_NUMBER, true, AUTHENTICATION, "INTERNATIONAL");
        verify(cloudwatchMetricsService)
                .emitMetricForNotificationError(
                        VERIFY_PHONE_NUMBER, UK_MOBILE_NUMBER, true, AUTHENTICATION, exception);
    }

    private String buildContactUsUrl() {
        return buildURI(configService.getFrontendBaseUrl(), configService.getContactUsLinkRoute())
                .toString();
    }

    private SQSMessage notifyRequestMessage(
            String destination, NotificationType template, String code, String messageId)
            throws Json.JsonException {
        var notifyRequest =
                new NotifyRequest(
                        destination,
                        template,
                        code,
                        SupportedLanguage.EN,
                        CommonTestVariables.SESSION_ID,
                        CommonTestVariables.CLIENT_SESSION_ID);

        // Inject the unique notification reference
        JsonObject jsonMap =
                objectMapper.readValue(
                        objectMapper.writeValueAsString(notifyRequest), JsonObject.class);
        jsonMap.addProperty("unique_notification_reference", TEST_UNIQUE_NOTIFICATION_REFERENCE);

        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(new Gson().toJson(jsonMap));
        sqsMessage.setMessageId(messageId);

        return sqsMessage;
    }

    private SQSEvent notifyRequestEvent(String destination, NotificationType template, String code)
            throws Json.JsonException {
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(
                singletonList(notifyRequestMessage(destination, template, code, TEST_MESSAGE_ID)));
        return sqsEvent;
    }
}
