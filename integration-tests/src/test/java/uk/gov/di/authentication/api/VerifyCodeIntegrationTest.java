package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.SessionHelper;
import uk.gov.di.entity.NotificationType;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.entity.VerifyCodeRequest;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class VerifyCodeIntegrationTest extends IntegrationTestEndpoints {

    private static final String VERIFY_CODE_ENDPOINT = "/verify-code";
    public static final String EMAIL_ADDRESS = "test@test.com";

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyEmailAndReturn200() throws IOException {
        String sessionId = SessionHelper.createSession();
        SessionHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = SessionHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        Response response = sendRequest(sessionId, codeRequest);
        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldCallVerifyCodeEndpointAndReturn200WitUpdatedStateWhenCodeHasExpired()
            throws IOException, InterruptedException {
        String sessionId = SessionHelper.createSession();
        SessionHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = SessionHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        TimeUnit.SECONDS.sleep(3);
        Response response = sendRequest(sessionId, codeRequest);

        assertEquals(200, response.getStatus());
        SessionState expectedState =
                new ObjectMapper()
                        .readValue(response.readEntity(String.class), Session.class)
                        .getState();
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, expectedState);
    }

    @Test
    public void shouldReturn200WithNewStateWhenUserTriesCodeThatTheyHaveAlreadyUsed()
            throws IOException {
        String sessionId = SessionHelper.createSession();
        SessionHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        String code = SessionHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        Response response = sendRequest(sessionId, codeRequest);
        assertEquals(200, response.getStatus());

        Response response2 = sendRequest(sessionId, codeRequest);
        assertEquals(200, response2.getStatus());

        SessionState expectedState =
                new ObjectMapper()
                        .readValue(response2.readEntity(String.class), Session.class)
                        .getState();
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, expectedState);
    }

    private Response sendRequest(String sessionId, VerifyCodeRequest codeRequest) {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + VERIFY_CODE_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);

        return invocationBuilder
                .headers(headers)
                .post(Entity.entity(codeRequest, MediaType.APPLICATION_JSON));
    }
}
