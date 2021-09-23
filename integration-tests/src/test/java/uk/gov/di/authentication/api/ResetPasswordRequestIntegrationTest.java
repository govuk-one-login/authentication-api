package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.authentication.helpers.httpstub.HttpStubExtension;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;

import java.io.IOException;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_SENT;

public class ResetPasswordRequestIntegrationTest extends IntegrationTestEndpoints {

    private static final String RESET_PASSWORD_ENDPOINT = "/reset-password-request";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @RegisterExtension
    public static final HttpStubExtension notifyStub = new HttpStubExtension(8888);

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200() throws IOException {
        registerEmail();
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, email);
        RedisHelper.setSessionState(sessionId, AUTHENTICATION_REQUIRED);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", API_KEY);
        Response response =
                RequestHelper.request(
                        RESET_PASSWORD_ENDPOINT, new ResetPasswordRequest(email), headers);
        await().atMost(1, MINUTES)
                .untilAsserted(() -> assertThat(notifyStub.getCountOfRequests(), equalTo(1)));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        BaseAPIResponse resetPasswordResponse =
                objectMapper.readValue(responseString, BaseAPIResponse.class);
        assertEquals(RESET_PASSWORD_LINK_SENT, resetPasswordResponse.getSessionState());
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn400WhenInvalidState() throws IOException {
        registerEmail();
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, email);
        RedisHelper.setSessionState(sessionId, NEW);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", API_KEY);

        Response response =
                RequestHelper.request(
                        RESET_PASSWORD_ENDPOINT, new ResetPasswordRequest(email), headers);

        assertEquals(400, response.getStatus());
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
