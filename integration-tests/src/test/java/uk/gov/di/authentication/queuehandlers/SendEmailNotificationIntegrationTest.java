package uk.gov.di.authentication.queuehandlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.helpers.httpstub.HttpStubExtension;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.services.AwsSqsClient;

import java.util.Optional;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;

public class SendEmailNotificationIntegrationTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    @RegisterExtension
    public final HttpStubExtension notifyStub =
            new HttpStubExtension(8888) {
                {
                    register(
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
                                    + "    \"id\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                    + "    \"version\": 1,"
                                    + "    \"uri\": \"http://localhost:8888/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                                    + "  }"
                                    + "}");
                }
            };

    @Test
    void shouldCallNotifyWhenValidRequestIsAddedToQueue()
            throws JsonProcessingException, InterruptedException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL);

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
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals(TEST_EMAIL_ADDRESS, personalisation.get("email-address").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }
}
