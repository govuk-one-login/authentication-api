package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ClientRegistrationResponse;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ClientRegistrationIntegrationTest extends IntegrationTestEndpoints {

    private static final String REGISTER_ENDPOINT = "/connect/register";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallRegisterEndpointAndReturn200() throws JsonProcessingException {
        ClientRegistrationRequest clientRequest =
                new ClientRegistrationRequest(
                        "The test client",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        "public-key",
                        singletonList("openid"));
        Response response = sendRequest(clientRequest);
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(
                        response.readEntity(String.class), ClientRegistrationResponse.class);

        assertEquals(200, response.getStatus());
        assertTrue(DynamoHelper.clientExists(clientResponse.getClientId()));
    }

    private Response sendRequest(ClientRegistrationRequest clientRequest) {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + REGISTER_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();

        return invocationBuilder
                .headers(headers)
                .post(Entity.entity(clientRequest, MediaType.APPLICATION_JSON));
    }
}
