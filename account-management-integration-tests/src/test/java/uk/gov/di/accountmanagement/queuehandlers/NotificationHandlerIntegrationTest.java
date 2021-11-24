package uk.gov.di.accountmanagement.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.basetest.NotifyIntegrationTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandlerIntegrationTest extends NotifyIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private static final NotificationHandler handler =
            new NotificationHandler(configurationService);

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534");

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals(TEST_EMAIL_ADDRESS, personalisation.get("email-address").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534");

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }
}
