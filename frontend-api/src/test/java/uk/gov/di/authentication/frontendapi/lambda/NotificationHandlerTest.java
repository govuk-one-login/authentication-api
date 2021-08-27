package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.di.authentication.frontendapi.entity.NotifyRequest;
import uk.gov.di.authentication.frontendapi.services.NotificationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567891";
    private static final String TEMPLATE_ID = "fdsfdssd";
    private static final String CODE = "123456";
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private NotificationHandler handler;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        handler = new NotificationHandler(notificationService, configService);
    }

    @Test
    public void shouldSuccessfullyProcessEmailMessageFromSQSQueue()
            throws JsonProcessingException, NotificationClientException {
        when(notificationService.getNotificationTemplateId(VERIFY_EMAIL)).thenReturn(TEMPLATE_ID);

        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, TEMPLATE_ID);
    }

    @Test
    public void shouldSuccessfullyProcessPhoneMessageFromSQSQueue()
            throws JsonProcessingException, NotificationClientException {
        when(notificationService.getNotificationTemplateId(VERIFY_PHONE_NUMBER))
                .thenReturn(TEMPLATE_ID);

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(notifyRequest.getDestination(), personalisation, TEMPLATE_ID);
    }

    @Test
    public void shouldThrowExceptionIfUnableToProcessMessageFromQueue() {
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
    public void shouldThrowExceptionIfNotifyIsUnableToSendEmail()
            throws JsonProcessingException, NotificationClientException {
        when(notificationService.getNotificationTemplateId(VERIFY_EMAIL)).thenReturn(TEMPLATE_ID);

        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, TEMPLATE_ID);

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
    public void shouldThrowExceptionIfNotifyIsUnableToSendText()
            throws JsonProcessingException, NotificationClientException {
        when(notificationService.getNotificationTemplateId(VERIFY_PHONE_NUMBER))
                .thenReturn(TEMPLATE_ID);

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendText(TEST_PHONE_NUMBER, personalisation, TEMPLATE_ID);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending with Notify using NotificationType: VERIFY_PHONE_NUMBER",
                exception.getMessage());
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
