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
import uk.gov.di.entity.LoginRequest;
import uk.gov.di.entity.LoginResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.entity.SessionState.AUTHENTICATED;

public class LoginIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGIN_ENDPOINT = "/login";
    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallLoginEndpointAndReturn200() throws IOException {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + LOGIN_ENDPOINT);
        String sessionId = SessionHelper.createSession();
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);

        LoginRequest request =
                new LoginRequest("joe.bloggs@digital.cabinet-office.gov.uk", "password");

        Response response =
                invocationBuilder
                        .headers(headers)
                        .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        LoginResponse loginResponse = objectMapper.readValue(responseString, LoginResponse.class);
        assertEquals(AUTHENTICATED, loginResponse.getSessionState());
    }
}
