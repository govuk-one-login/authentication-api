package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UpdateClientConfigIntegrationTest extends IntegrationTestEndpoints {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CLIENT_ID = "client-id-1";
    private static final String BASE_UPDATE_ENDPOINT = "/oidc/clients";
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @Test
    public void shouldUpdateClientNameSuccessfully() throws JsonProcessingException {
        DynamoHelper.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList("http://localhost:1000/redirect"),
                singletonList("test-client@test.com"),
                singletonList("openid"),
                VALID_PUBLIC_CERT,
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                AuthenticationValues.MEDIUM_LEVEL.getValue());

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
    public void shouldReturn400WhenClientIsUnauthorized() {
        UpdateClientConfigRequest updateRequest = new UpdateClientConfigRequest();
        updateRequest.setClientName("new-client-name");

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + BASE_UPDATE_ENDPOINT + "/" + CLIENT_ID)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .post(Entity.entity(updateRequest, MediaType.APPLICATION_JSON));

        assertEquals(400, response.getStatus());
        assertEquals(
                OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString(),
                response.readEntity(String.class));
    }
}
