package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567891";
    private static final String NOTIFY_PHONE_NUMBER = "01234567899";
    private static final String BUCKET_NAME = "test-s3-bucket";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-us";
    private static final URI GOV_UK_ACCOUNTS_URL = URI.create("gov-uk-accounts-url");
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final S3Client s3Client = mock(S3Client.class);
    private NotificationHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(NOTIFY_PHONE_NUMBER));
        when(configService.getSmoketestBucketName()).thenReturn(BUCKET_NAME);
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        when(configService.getGovUKAccountsURL()).thenReturn(GOV_UK_ACCOUNTS_URL);
        handler = new NotificationHandler(notificationService, configService, s3Client);
    }

    @Test
    void shouldSuccessfullyProcessEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=confirmEmailAddressEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL, SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationEmailFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS, PASSWORD_RESET_CONFIRMATION, SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetConfirmationEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(
                        TEST_EMAIL_ADDRESS,
                        personalisation,
                        PASSWORD_RESET_CONFIRMATION,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationSMSFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        var notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER, PASSWORD_RESET_CONFIRMATION_SMS, SupportedLanguage.EN);
        var sqsEvent = generateSQSEvent(objectMapper.writeValueAsString(notifyRequest));
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetConfirmationSms";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = Map.of("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendText(
                        TEST_PHONE_NUMBER,
                        personalisation,
                        PASSWORD_RESET_CONFIRMATION_SMS,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessAccountCreatedConfirmationFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        String baseUrl = "http://account-management";
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=accountCreatedEmail";
        var govUKAccountsUrl = URI.create("https://www.gov.uk/account");
        when(configService.getAccountManagementURI()).thenReturn(baseUrl);
        when(configService.getGovUKAccountsURL()).thenReturn(govUKAccountsUrl);

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION, SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);
        personalisation.put("gov-uk-accounts-url", govUKAccountsUrl.toString());

        verify(notificationService)
                .sendEmail(
                        TEST_EMAIL_ADDRESS,
                        personalisation,
                        ACCOUNT_CREATED_CONFIRMATION,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        notifyRequest.getDestination(),
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldThrowExceptionIfUnableToProcessMessageFromQueue() {
        SQSEvent sqsEvent = generateSQSEvent("");

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error when mapping message from queue to a NotifyRequest", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotifyIsUnableToSendEmail()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=confirmEmailAddressEmail";

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL, SupportedLanguage.EN);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending with Notify using NotificationType: VERIFY_EMAIL",
                exception.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotifyIsUnableToSendText()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendText(
                        TEST_PHONE_NUMBER,
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        SupportedLanguage.EN);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending with Notify using NotificationType: VERIFY_PHONE_NUMBER",
                exception.getMessage());
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        NOTIFY_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        notifyRequest.getDestination(),
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        SupportedLanguage.EN);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(NOTIFY_PHONE_NUMBER).build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        notifyRequest.getDestination(),
                        personalisation,
                        MFA_SMS,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(NOTIFY_PHONE_NUMBER, MFA_SMS, "654321", SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        notifyRequest.getDestination(),
                        personalisation,
                        MFA_SMS,
                        SupportedLanguage.EN);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(NOTIFY_PHONE_NUMBER).build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void
            shouldSuccessfullyProcessAccountConfirmationRequestFromSQSQueueAndNotWriteOTPToS3WhenTestClient()
                    throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", buildContactUsUrl("accountCreatedEmail"));
        personalisation.put("gov-uk-accounts-url", GOV_UK_ACCOUNTS_URL.toString());

        verify(notificationService)
                .sendEmail(
                        notifyRequest.getDestination(),
                        personalisation,
                        ACCOUNT_CREATED_CONFIRMATION,
                        SupportedLanguage.EN);
        var putObjectRequest =
                PutObjectRequest.builder().bucket(BUCKET_NAME).key(NOTIFY_PHONE_NUMBER).build();
        verify(s3Client, times(0)).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void shouldSuccessfullyProcessPasswordResetWithCodeMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        RESET_PASSWORD_WITH_CODE,
                        "654321",
                        SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetRequestEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(
                        TEST_EMAIL_ADDRESS,
                        personalisation,
                        RESET_PASSWORD_WITH_CODE,
                        SupportedLanguage.EN);
    }

    @Test
    void shouldSuccessfullyProcessVerifyChangeHowGetSecurityCodesMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        "654321",
                        SupportedLanguage.EN);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());

        verify(notificationService)
                .sendEmail(
                        TEST_EMAIL_ADDRESS,
                        personalisation,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        SupportedLanguage.EN);
    }

    private String buildContactUsUrl(String referer) {
        var queryParam = Map.of("referer", referer);
        return buildURI(
                        configService.getFrontendBaseUrl(),
                        configService.getContactUsLinkRoute(),
                        queryParam)
                .toString();
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
