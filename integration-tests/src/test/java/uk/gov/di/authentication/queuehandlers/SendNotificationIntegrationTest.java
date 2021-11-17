package uk.gov.di.authentication.queuehandlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class SendNotificationIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private static final AwsSqsClient client =
            new AwsSqsClient(
                    "eu-west-2",
                    "http://localhost:45678/123456789012/local-email-notification-queue",
                    Optional.of("http://localhost:45678/"));

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(8888, objectMapper);

    @BeforeEach
    public void setUp() {
        notifyStub.init();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534")));

        JsonNode request = notifyStub.waitForRequest(90);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals(TEST_EMAIL_ADDRESS, personalisation.get("email-address").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534")));

        JsonNode request = notifyStub.waitForRequest(90);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidMfaRequestIsAddedToQueue() throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, "162534")));

        JsonNode request = notifyStub.waitForRequest(90);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidResetPasswordRequestIsAddedToQueue()
            throws JsonProcessingException {
        String code = new CodeGeneratorService().twentyByteEncodedRandomCode();

        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, code)));

        JsonNode request = notifyStub.waitForRequest(90);
        JsonNode personalisation = request.get("personalisation");
        assertThat(personalisation.get("reset-password-link").asText(), containsString(code));
        assertThat(
                personalisation.get("reset-password-link").asText(),
                startsWith("http://localhost:3000/reset-password?code="));
    }

    @Test
    void shouldCallNotifyWhenValidAccountCreatedRequestIsAddedToQueue()
            throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION)));

        JsonNode request = notifyStub.waitForRequest(90);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals("http://localhost:3000/", personalisation.get("sign-in-page-url").asText());
    }
}
