package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AuthorisationIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTHORIZE_ENDPOINT = "/authorize";

    @Test
    public void shouldSetCookieAndReturn302WhenAuthorisationSucceeds() {

        String clientID = "test-client";
        KeyPair keyPair = generateRsaKeyPair();
        setUpDynamo(keyPair, clientID);

        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + AUTHORIZE_ENDPOINT)
                        .queryParam("response_type", "code")
                        .queryParam("redirect_uri", "localhost")
                        .queryParam("state", "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU")
                        .queryParam("client_id", "test-client")
                        .queryParam("scope", "openid")
                        .request()
                        .get();

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
    }

    private void setUpDynamo(KeyPair keyPair, String clientID) {
        DynamoHelper.registerClient(
                clientID,
                "test-client",
                singletonList("localhost"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
