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
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @Test
    public void shouldCallRegisterEndpointAndReturn200() throws JsonProcessingException {
        ClientRegistrationRequest clientRequest =
                new ClientRegistrationRequest(
                        "The test client",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        VALID_PUBLIC_CERT,
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
