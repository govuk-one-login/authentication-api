package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.API_KEY;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;

public class ResetPasswordIntegrationTest {

    private static final String RESET_PASSWORD_ENDPOINT = "/reset-password";
    private static final String PASSWORD = "Pa55word";
    private static final String CODE = "0123456789";

    @Test
    public void shouldCallUpdatePasswordAndReturn200() {
        ResetPasswordWithCodeRequest requestBody = new ResetPasswordWithCodeRequest(CODE, PASSWORD);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("X-API-Key", API_KEY);
        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + RESET_PASSWORD_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(headers)
                        .post(Entity.entity(requestBody, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());
    }
}
