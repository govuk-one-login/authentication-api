package uk.gov.di.authentication.sharedtest.extensions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class NotifyStubExtension extends HttpStubExtension {

    private final ObjectMapper objectMapper;

    public NotifyStubExtension(int port, ObjectMapper objectMapper) {
        super(port);
        this.objectMapper = objectMapper;
    }

    public void init() {
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
                        + "  \"uri\": \"http://localhost:19999/v2/notifications/a-message-id\","
                        + "  \"template\": {"
                        + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                        + "    \"version\": 1,"
                        + "    \"uri\": \"http://localhost:19999/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                        + "  }"
                        + "}");
        register(
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
                        + "  \"uri\": \"http://localhost:19999/v2/notifications/a-message-id\","
                        + "  \"template\": {"
                        + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                        + "    \"version\": 1,"
                        + "    \"uri\": \"http://localhost:19999/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                        + "  }"
                        + "}");
    }

    public JsonNode waitForRequest(int timeoutInSeconds) throws JsonProcessingException {
        await().atMost(timeoutInSeconds, SECONDS)
                .untilAsserted(() -> assertThat(getCountOfRequests(), equalTo(1)));

        return objectMapper.readTree(getLastRequest().getEntity());
    }
}
