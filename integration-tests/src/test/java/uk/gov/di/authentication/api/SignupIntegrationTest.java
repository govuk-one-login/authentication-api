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
import uk.gov.di.authentication.helpers.SessionHelper;
import uk.gov.di.entity.SignupRequest;
import uk.gov.di.entity.SignupResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;

public class SignupIntegrationTest extends IntegrationTestEndpoints {

    private static final String SIGNUP_ENDPOINT = "/signup";
    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallSignupEndpointAndReturn200() throws IOException {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + SIGNUP_ENDPOINT);
        String sessionId = SessionHelper.createSession();
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);

        SignupRequest request =
                new SignupRequest("joe.bloggs@digital.cabinet-office.gov.uk", "1-valid-password");

        Response response =
                invocationBuilder
                        .headers(headers)
                        .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        SignupResponse signupResponse =
                objectMapper.readValue(responseString, SignupResponse.class);
        assertEquals(TWO_FACTOR_REQUIRED, signupResponse.getSessionState());
        assertTrue(DynamoHelper.userExists("joe.bloggs@digital.cabinet-office.gov.uk"));
    }
}
