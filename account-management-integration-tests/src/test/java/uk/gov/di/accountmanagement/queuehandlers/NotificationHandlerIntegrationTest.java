package uk.gov.di.accountmanagement.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.basetest.NotifyIntegrationTest;

import java.security.SecureRandom;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasField;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;

public class NotificationHandlerIntegrationTest extends NotifyIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";

    private static final NotificationHandler handler =
            new NotificationHandler(configurationService);
    public final String CODE = format("%06d", new SecureRandom().nextInt(999999));

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, CODE);

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);

        assertThat(request, hasField("personalisation"));
        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation, hasFieldWithValue("email-address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, CODE);

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        assertThat(request, hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER)));
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
    }
}
