package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenIntegrationTest extends IntegrationTestEndpoints {

    private static final String TOKEN_ENDPOINT = "/token";

    @Test
    public void shouldCallTokenResourceAndReturn200() {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + TOKEN_ENDPOINT);

        Invocation.Builder invocationBuilder = webTarget.request(MediaType.TEXT_PLAIN);
        Response response =
                invocationBuilder.post(
                        Entity.entity(
                                "code=123456789&client_id=test-id&client_secret=test-secret",
                                MediaType.TEXT_PLAIN));

        assertEquals(200, response.getStatus());
    }
}
