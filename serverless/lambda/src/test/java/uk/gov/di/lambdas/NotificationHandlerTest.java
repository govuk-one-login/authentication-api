package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.NotificationService;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;

public class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
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
    public void shouldSuccessfullyProcessMessageFromSQSQueue()
            throws JsonProcessingException, NotificationClientException {
        when(configService.getNotificationTemplateId(VERIFY_EMAIL)).thenReturn(TEMPLATE_ID);
        when(notificationService.generateSixDigitCode()).thenReturn(CODE);

        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, null);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", CODE);
        personalisation.put("email-address", notifyRequest.getDestination());

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, TEMPLATE_ID);
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
        when(configService.getNotificationTemplateId(VERIFY_EMAIL)).thenReturn(TEMPLATE_ID);
        when(notificationService.generateSixDigitCode()).thenReturn(CODE);

        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, null);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", CODE);
        personalisation.put("email-address", notifyRequest.getDestination());
        doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, TEMPLATE_ID);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals("Error when sending email via Notify", exception.getMessage());
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
