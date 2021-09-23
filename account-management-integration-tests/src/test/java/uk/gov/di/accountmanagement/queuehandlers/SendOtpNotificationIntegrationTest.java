package uk.gov.di.accountmanagement.queuehandlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class SendOtpNotificationIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

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
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534");

        AwsSqsClient client =
                new AwsSqsClient(
                        "eu-west-2",
                        "http://localhost:45678/123456789012/local-account-management-notification-queue",
                        Optional.of("http://localhost:45678/"));

        ObjectMapper objectMapper = new ObjectMapper();
        client.send(objectMapper.writeValueAsString(notifyRequest));

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

        AwsSqsClient client =
                new AwsSqsClient(
                        "eu-west-2",
                        "http://localhost:45678/123456789012/local-email-notification-queue",
                        Optional.of("http://localhost:45678/"));

        ObjectMapper objectMapper = new ObjectMapper();
        client.send(objectMapper.writeValueAsString(notifyRequest));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }
}
