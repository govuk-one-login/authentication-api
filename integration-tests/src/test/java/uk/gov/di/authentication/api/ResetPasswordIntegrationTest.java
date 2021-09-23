package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.httpstub.HttpStubExtension;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.API_KEY;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;

public class ResetPasswordIntegrationTest {

    private static final String RESET_PASSWORD_ENDPOINT = "/reset-password";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PASSWORD = "Pa55word";
    private static final String CODE = "0123456789";

    @RegisterExtension
    public static final HttpStubExtension notifyStub = new HttpStubExtension(8888);

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    public void shouldUpdatePasswordAndReturn200() {
        registerEmail();
        String subject = "new-subject";
        ResetPasswordWithCodeRequest requestBody = new ResetPasswordWithCodeRequest(CODE, PASSWORD);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1", new Subject(subject));
        RedisHelper.generateAndSavePasswordResetCode(subject, CODE, 900l);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("X-API-Key", API_KEY);
        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + RESET_PASSWORD_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(headers)
                        .post(Entity.entity(requestBody, MediaType.APPLICATION_JSON));
        await().atMost(1, MINUTES)
                .untilAsserted(() -> assertThat(notifyStub.getCountOfRequests(), equalTo(1)));

        assertEquals(200, response.getStatus());
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
}
