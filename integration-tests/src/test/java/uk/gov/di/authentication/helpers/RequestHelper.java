package uk.gov.di.authentication.helpers;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import static uk.gov.di.authentication.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;

public class RequestHelper {

    public static Response request(
            String endpoint, Object body, MultivaluedMap<String, Object> headers) {
        return request(ROOT_RESOURCE_URL, endpoint, body, headers);
    }

    public static Response request(
            String rootResourceURL,
            String endpoint,
            Object body,
            MultivaluedMap<String, Object> headers) {
        return ClientBuilder.newClient()
                .target(rootResourceURL + endpoint)
                .request(MediaType.APPLICATION_JSON)
                .headers(headers)
                .post(Entity.entity(body, MediaType.APPLICATION_JSON));
    }
}
