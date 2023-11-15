package uk.gov.di.orchestration.sharedtest.extensions;

import com.google.gson.JsonElement;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

import java.util.List;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class NotifyStubExtension extends HttpStubExtension {

    private final Json objectMapper;

    public NotifyStubExtension(int port, Json objectMapper) {
        super(port);
        this.objectMapper = objectMapper;
    }

    public NotifyStubExtension(Json objectMapper) {
        super();
        this.objectMapper = objectMapper;
    }

    public void init() {
        register(
                "/v2/notifications/email",
                201,
                "application/json",
                format(
                        "{"
                                + "  \"id\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                + "  \"reference\": \"STRING\","
                                + "  \"content\": {"
                                + "    \"subject\": \"SUBJECT TEXT\","
                                + "    \"body\": \"MESSAGE TEXT\",\n"
                                + "    \"from_email\": \"SENDER EMAIL\""
                                + "  },"
                                + "  \"uri\": \"http://localhost:%1$d/v2/notifications/a-message-id\","
                                + "  \"template\": {"
                                + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                                + "    \"version\": 1,"
                                + "    \"uri\": \"http://localhost:%1$d/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                                + "  }"
                                + "}",
                        getHttpPort()));
        register(
                "/v2/notifications/sms",
                201,
                "application/json",
                format(
                        "{"
                                + "  \"id\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                + "  \"reference\": \"STRING\","
                                + "  \"content\": {"
                                + "    \"body\": \"MESSAGE TEXT\",\n"
                                + "    \"from_number\": \"SENDER\""
                                + "  },"
                                + "  \"uri\": \"http://localhost:%1$d}/v2/notifications/a-message-id\","
                                + "  \"template\": {"
                                + "    \"id\": \"f33517ff-2a88-4f6e-b855-c550268ce08a\","
                                + "    \"version\": 1,"
                                + "    \"uri\": \"http://localhost:%1$d/v2/template/f33517ff-2a88-4f6e-b855-c550268ce08a\""
                                + "  }"
                                + "}",
                        getHttpPort()));
    }

    public JsonElement waitForRequest(int timeoutInSeconds) throws Json.JsonException {
        await().atMost(timeoutInSeconds, SECONDS)
                .untilAsserted(() -> assertThat(getCountOfRequests(), equalTo(1)));

        return objectMapper.readValue(getLastRequest().getEntity(), JsonElement.class);
    }

    public List<JsonElement> waitForNumberOfRequests(int timeoutInSeconds, int numberOfRequests) {
        await().atMost(timeoutInSeconds, SECONDS)
                .untilAsserted(() -> assertThat(getCountOfRequests(), equalTo(numberOfRequests)));

        return getRecordedRequests().stream()
                .map(
                        r -> {
                            try {
                                return objectMapper.readValue(r.getEntity(), JsonElement.class);
                            } catch (Json.JsonException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .collect(Collectors.toList());
    }
}
