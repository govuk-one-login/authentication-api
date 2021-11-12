package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwksIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String JWKS_ENDPOINT = "/.well-known/jwks.json";

    @Test
    public void shouldReturn200AndClientInfoResponseForValidClient() throws ParseException {
        Client client = ClientBuilder.newClient();
        Response response = client.target(ROOT_RESOURCE_URL + JWKS_ENDPOINT).request().get();

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        assertTrue(JWKSet.parse(responseString).getKeys().size() == 1);
    }
}
