package uk.gov.di.accountmanagement.queuehandlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.helpers.httpstub.HttpStubExtension;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.NotifyRequest;

import java.util.Optional;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class SendOtpNotificationIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    @RegisterExtension
    public static final HttpStubExtension notifyStub = new HttpStubExtension(8888);

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        registerEmail();
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534");

        AwsSqsClient client =
                new AwsSqsClient(
                        "eu-west-2",
                        "http://localhost:45678/123456789012/local-account-management-notification-queue",
                        Optional.of("http://localhost:45678/"));

        ObjectMapper objectMapper = new ObjectMapper();
        client.send(objectMapper.writeValueAsString(notifyRequest));

        await().atMost(1, MINUTES)
                .untilAsserted(() -> assertThat(notifyStub.getCountOfRequests(), equalTo(1)));

        JsonNode request = objectMapper.readTree(notifyStub.getLastRequest().getEntity());
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals(TEST_EMAIL_ADDRESS, personalisation.get("email-address").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        registerText();
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534");

        AwsSqsClient client =
                new AwsSqsClient(
                        "eu-west-2",
                        "http://localhost:45678/123456789012/local-email-notification-queue",
                        Optional.of("http://localhost:45678/"));

        ObjectMapper objectMapper = new ObjectMapper();
        client.send(objectMapper.writeValueAsString(notifyRequest));

        await().atMost(1, MINUTES)
                .untilAsserted(() -> assertThat(notifyStub.getCountOfRequests(), equalTo(1)));

        JsonNode request = objectMapper.readTree(notifyStub.getLastRequest().getEntity());
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    private void registerEmail() {
        notifyStub.register(
                "/v2/notifications/email",
                201,
                "application/json",
                "{"
                        + "  \"id\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"reference\": \"STRING\","
                        + "  \"content\": {"
                        + "    \"subject\": \"SUBJECT TEXT\","
                        + "    \"body\": \"MESSAGE TEXT\",\n"
                        + "    \"from_email\": \"SENDER EMAIL\""
                        + "  },"
                        + "  \"uri\": \"http://localhost:8888/v2/notifications/a-message-id\","
                        + "  \"template\": {"
                        + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                        + "    \"version\": 1,"
                        + "    \"uri\": \"http://localhost:8888/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                        + "  }"
                        + "}");
    }

    private void registerText() {
        notifyStub.register(
                "/v2/notifications/sms",
                201,
                "application/json",
                "{"
                        + "  \"id\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"reference\": \"STRING\","
                        + "  \"content\": {"
                        + "    \"body\": \"MESSAGE TEXT\",\n"
                        + "    \"from_number\": \"SENDER\""
                        + "  },"
                        + "  \"uri\": \"http://localhost:8888/v2/notifications/a-message-id\","
                        + "  \"template\": {"
                        + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                        + "    \"version\": 1,"
                        + "    \"uri\": \"http://localhost:8888/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                        + "  }"
                        + "}");
    }
}
