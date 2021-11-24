package uk.gov.di.authentication.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.sharedtest.basetest.NotifyIntegrationTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class SendNotificationIntegrationTest extends NotifyIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private final NotificationHandler handler = new NotificationHandler(configurationService);

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {

        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534")),
                mock(Context.class));

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
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534")),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidMfaRequestIsAddedToQueue() throws JsonProcessingException {
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, "162534")),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidResetPasswordRequestIsAddedToQueue()
            throws JsonProcessingException {
        String code = new CodeGeneratorService().twentyByteEncodedRandomCode();

        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, code)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertThat(personalisation.get("reset-password-link").asText(), containsString(code));
        assertThat(
                personalisation.get("reset-password-link").asText(),
                startsWith("http://localhost:3000/reset-password?code="));
    }

    @Test
    void shouldCallNotifyWhenValidAccountCreatedRequestIsAddedToQueue()
            throws JsonProcessingException {
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals("http://localhost:3000/", personalisation.get("sign-in-page-url").asText());
    }
}
