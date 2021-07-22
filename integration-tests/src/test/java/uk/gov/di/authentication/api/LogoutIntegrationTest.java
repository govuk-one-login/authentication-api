package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.helpers.IDTokenGenerator;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LogoutIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGOUT_ENDPOINT = "/logout";

    @Test
    public void shouldReturn302AndRedirectToDefaultLogoutUri() throws JOSEException {
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        SignedJWT signedJWT =
                IDTokenGenerator.generateIDToken(
                        "client-id", new Subject(), "http://localhost/issuer", signingKey);
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + LOGOUT_ENDPOINT)
                        .queryParam("id_token_hint", signedJWT.serialize())
                        .queryParam("post_logout_redirect_uri", "http://localhost/redirect")
                        .queryParam("state", "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU")
                        .request()
                        .get();

        assertEquals(302, response.getStatus());
    }
}
