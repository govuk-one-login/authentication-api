package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenResourceIntegrationTest {

    private static final String LOCAL_TOKEN_ENDPOINT_FORMAT =
            "http://localhost:45678/restapis/%s/local/_user_request_";
    private static final String LOCAL_API_GATEWAY_ID =
            Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    private static final String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(String.format(LOCAL_TOKEN_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));

    private static final String TOKEN_RESOURCE = "/token";

    @Test
    public void shouldCallTokenResourceAndReturn200() {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + TOKEN_RESOURCE);

        Invocation.Builder invocationBuilder = webTarget.request(MediaType.TEXT_PLAIN);
        Response response =
                invocationBuilder.post(
                        Entity.entity(
                                "code=123456789&client_id=test-id&client_secret=test-secret",
                                MediaType.TEXT_PLAIN));

        assertEquals(200, response.getStatus());
    }
}
