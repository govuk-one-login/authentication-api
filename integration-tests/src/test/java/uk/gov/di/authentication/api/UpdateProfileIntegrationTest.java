package uk.gov.di.authentication.api;

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
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.UpdateProfileRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.entity.UpdateProfileType.ADD_PHONE_NUMBER;

public class UpdateProfileIntegrationTest extends IntegrationTestEndpoints {

    private static final String UPDATE_PROFILE_ENDPOINT = "/update-profile";
    private static final String EMAIL_ADDRESS = "test@test.com";

    @Test
    public void shouldCallUpdateProfileEndpointAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1");

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, "0123456789");

        Response response = sendRequest(sessionId, request);
        assertEquals(200, response.getStatus());
    }

    private Response sendRequest(String sessionId, UpdateProfileRequest request) {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + UPDATE_PROFILE_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);

        return invocationBuilder
                .headers(headers)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
    }
}
