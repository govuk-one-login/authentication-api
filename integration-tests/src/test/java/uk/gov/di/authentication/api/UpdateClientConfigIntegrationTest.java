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
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.UpdateClientConfigRequest;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UpdateClientConfigIntegrationTest extends IntegrationTestEndpoints {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CLIENT_ID = "client-id-1";
    private static final String BASE_UPDATE_ENDPOINT = "/oidc/clients";

    @Test
    public void shouldCallRegisterAndUpdateClientNameSuccessfully() throws JsonProcessingException {
        DynamoHelper.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList("http://localhost:1000/redirect"),
                singletonList("test-client@test.com"),
                singletonList("openid"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"));

        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest.setClientName("new-client-name");

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + BASE_UPDATE_ENDPOINT + "/" + CLIENT_ID)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .post(Entity.entity(updateRequest, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());
        ClientRegistrationResponse clientResponse =
                objectMapper.readValue(
                        response.readEntity(String.class), ClientRegistrationResponse.class);
        assertEquals("new-client-name", clientResponse.getClientName());
        assertEquals(CLIENT_ID, clientResponse.getClientId());
    }

    @Test
    public void shouldReturn401WhenClientIsUnauthorized() throws JsonProcessingException {
        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest.setClientName("new-client-name");

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + BASE_UPDATE_ENDPOINT + "/" + CLIENT_ID)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .post(Entity.entity(updateRequest, MediaType.APPLICATION_JSON));

        assertEquals(401, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1016),
                response.readEntity(String.class));
    }
}
