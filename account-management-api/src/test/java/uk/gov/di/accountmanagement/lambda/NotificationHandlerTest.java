package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.NotificationService;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.DELETE_ACCOUNT;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSWORD_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.PHONE_NUMBER_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;

class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-gov-uk-one-login";
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private NotificationHandler handler;
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        handler = new NotificationHandler(notificationService, configService);
    }

    @Test
    void shouldSuccessfullyProcessVerifyEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321", SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL);
    }

    @Test
    void shouldSuccessfullyProcessVerifyPhoneMessageFromSQSQueue()
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
                .sendText(TEST_PHONE_NUMBER, personalisation, VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldSuccessfullyProcessUpdateEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, EMAIL_UPDATED);
    }

    @Test
    void shouldSuccessfullyProcessUpdatePasswordMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, PASSWORD_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, PASSWORD_UPDATED);
    }

    @Test
    void shouldSuccessfullyProcessUpdatePhoneNumberMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, PHONE_NUMBER_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, PHONE_NUMBER_UPDATED);
    }

    @Test
    void shouldSuccessfullyProcessDeleteAccountMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, DELETE_ACCOUNT, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, DELETE_ACCOUNT);
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

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
