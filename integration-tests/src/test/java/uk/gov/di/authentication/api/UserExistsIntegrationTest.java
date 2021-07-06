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
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.CheckUserExistsResponse;
import uk.gov.di.entity.UserWithEmailRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.entity.SessionState.USER_NOT_FOUND;

public class UserExistsIntegrationTest extends IntegrationTestEndpoints {

    private static final String USEREXISTS_ENDPOINT = "/user-exists";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallUserExistsEndpointAndReturnAuthenticationRequestStateWhenUserExists()
            throws IOException {
        String emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        DynamoHelper.signUp(emailAddress, "password-1");
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);
        UserWithEmailRequest request = new UserWithEmailRequest(emailAddress);
        Response response = sendRequest(sessionId, request);

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
        assertEquals(AUTHENTICATION_REQUIRED, checkUserExistsResponse.getSessionState());
        assertTrue(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnUserNotFoundStateWhenUserDoesNotExist()
            throws IOException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);
        UserWithEmailRequest request = new UserWithEmailRequest(emailAddress);
        Response response = sendRequest(sessionId, request);

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
        assertEquals(USER_NOT_FOUND, checkUserExistsResponse.getSessionState());
        assertFalse(checkUserExistsResponse.doesUserExist());
    }

    private Response sendRequest(String sessionId, UserWithEmailRequest request) {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + USEREXISTS_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);

        return invocationBuilder
                .headers(headers)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
    }
}
