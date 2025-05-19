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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class NotificationHandlerTest {

    private static final String BUCKET_NAME = "test-s3-bucket";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-us";
    private static final URI GOV_UK_ACCOUNTS_URL = URI.create("gov-uk-accounts-url");
    private static final String TEST_UNIQUE_NOTIFICATION_REFERENCE =
            "known-unique-notification-reference";
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final S3Client s3Client = mock(S3Client.class);
    private NotificationHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();

    private static final String EXPECTED_REFERENCE =
            String.format(
                    "%s/%s",
                    TEST_UNIQUE_NOTIFICATION_REFERENCE, CommonTestVariables.CLIENT_SESSION_ID);

    @BeforeEach
    void setUp() {
        when(configService.getNotifyTestDestinations())
                .thenReturn(List.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(configService.getSmoketestBucketName()).thenReturn(BUCKET_NAME);
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        when(configService.getGovUKAccountsURL()).thenReturn(GOV_UK_ACCOUNTS_URL);
        handler = new NotificationHandler(notificationService, configService, s3Client);
    }

    @Test
    void shouldSuccessfullyProcessEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        SQSEvent sqsEvent = notifyRequestEvent(CommonTestVariables.EMAIL, VERIFY_EMAIL, "654321");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", CommonTestVariables.EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        VERIFY_EMAIL,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationEmailFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.EMAIL, PASSWORD_RESET_CONFIRMATION, null);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        PASSWORD_RESET_CONFIRMATION,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationSMSFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        var sqsEvent =
                notifyRequestEvent(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        PASSWORD_RESET_CONFIRMATION_SMS,
                        null);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = Map.of("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        PASSWORD_RESET_CONFIRMATION_SMS,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessAccountCreatedConfirmationFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        String baseUrl = "http://account-management";
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        var govUKAccountsUrl = URI.create("https://www.gov.uk/account");
        when(configService.getAccountManagementURI()).thenReturn(baseUrl);
        when(configService.getGovUKAccountsURL()).thenReturn(govUKAccountsUrl);

        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.EMAIL, ACCOUNT_CREATED_CONFIRMATION, null);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);
        personalisation.put("gov-uk-accounts-url", govUKAccountsUrl.toString());

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        ACCOUNT_CREATED_CONFIRMATION,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(
                        CommonTestVariables.UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldNotSendAnythingWhenATermsAndConditionsBulkEmail() throws Json.JsonException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.EMAIL, TERMS_AND_CONDITIONS_BULK_EMAIL, "");

        handler.handleRequest(sqsEvent, context);

        verifyNoInteractions(notificationService);
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
        SQSEvent sqsEvent = notifyRequestEvent(CommonTestVariables.EMAIL, VERIFY_EMAIL, "654321");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", CommonTestVariables.EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        VERIFY_EMAIL,
                        EXPECTED_REFERENCE);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending Notify email with NotificationType: VERIFY_EMAIL",
                exception.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotifyIsUnableToSendText()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(
                        CommonTestVariables.UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        EXPECTED_REFERENCE);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending Notify SMS with NotificationType: VERIFY_PHONE_NUMBER and country code: 44",
                exception.getMessage());
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(
                        CommonTestVariables.UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, "654321");

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        VERIFY_PHONE_NUMBER,
                        EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder()
                        .bucket(BUCKET_NAME)
                        .key(CommonTestVariables.UK_MOBILE_NUMBER)
                        .build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, "654321");

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        MFA_SMS,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, "654321");

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        personalisation,
                        MFA_SMS,
                        EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder()
                        .bucket(BUCKET_NAME)
                        .key(CommonTestVariables.UK_MOBILE_NUMBER)
                        .build();
        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void
            shouldSuccessfullyProcessAccountConfirmationRequestFromSQSQueueAndNotWriteOTPToS3WhenTestClient()
                    throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.EMAIL, ACCOUNT_CREATED_CONFIRMATION, null);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", buildContactUsUrl());
        personalisation.put("gov-uk-accounts-url", GOV_UK_ACCOUNTS_URL.toString());

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        ACCOUNT_CREATED_CONFIRMATION,
                        EXPECTED_REFERENCE);
        var putObjectRequest =
                PutObjectRequest.builder()
                        .bucket(BUCKET_NAME)
                        .key(CommonTestVariables.UK_MOBILE_NUMBER)
                        .build();
        verify(s3Client, times(0)).putObject(eq(putObjectRequest), any(RequestBody.class));
    }

    @Test
    void shouldSuccessfullyProcessPasswordResetWithCodeMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(CommonTestVariables.EMAIL, RESET_PASSWORD_WITH_CODE, "654321");
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", CommonTestVariables.EMAIL);
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        RESET_PASSWORD_WITH_CODE,
                        EXPECTED_REFERENCE);
    }

    @Test
    void shouldSuccessfullyProcessVerifyChangeHowGetSecurityCodesMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        SQSEvent sqsEvent =
                notifyRequestEvent(
                        CommonTestVariables.EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "654321");

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", CommonTestVariables.EMAIL);

        verify(notificationService)
                .sendEmail(
                        CommonTestVariables.EMAIL,
                        personalisation,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        EXPECTED_REFERENCE);
    }

    private String buildContactUsUrl() {
        return buildURI(configService.getFrontendBaseUrl(), configService.getContactUsLinkRoute())
                .toString();
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }

    private SQSEvent notifyRequestEvent(String destination, NotificationType template, String code)
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

        return generateSQSEvent(new Gson().toJson(jsonMap));
    }
}
