package uk.gov.di.authentication.helpers;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import static uk.gov.di.authentication.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;

public class RequestHelper {

    public static Response requestWithSession(String endpoint, Object body, String sessionId) {
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);

        return ClientBuilder.newClient()
                .target(ROOT_RESOURCE_URL + endpoint)
                .request(MediaType.APPLICATION_JSON)
                .headers(headers)
                .post(Entity.entity(body, MediaType.APPLICATION_JSON));
    }
}
