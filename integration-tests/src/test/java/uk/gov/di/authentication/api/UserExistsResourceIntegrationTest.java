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
import uk.gov.di.entity.CheckUserExistsRequest;
import uk.gov.di.entity.CheckUserExistsResponse;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UserExistsResourceIntegrationTest {

    private final static String LOCAL_ENDPOINT_FORMAT = "http://localhost:45678/restapis/%s/local/_user_request_";
    private final static String LOCAL_API_GATEWAY_ID = Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    private final static String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL")).orElse(String.format(LOCAL_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));

    private final static String USEREXISTS_RESOURCE = "/userexists";
    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallUserExistsResourceAndReturn200() throws JsonProcessingException {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + USEREXISTS_RESOURCE);

        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id",  UUID.randomUUID().toString());

        CheckUserExistsRequest request = new CheckUserExistsRequest("joe.bloggs@digital.cabinet-office.gov.uk");

        Response response = invocationBuilder
                .headers(headers)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse = objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
    }
}
