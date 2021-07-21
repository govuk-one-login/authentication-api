package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
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
                          singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"));

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + REGISTER_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .post(Entity.entity(clientRequest, MediaType.APPLICATION_JSON));

        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(
                        response.readEntity(String.class), ClientRegistrationResponse.class);

        assertEquals(200, response.getStatus());
        assertTrue(DynamoHelper.clientExists(clientResponse.getClientId()));
    }
}
