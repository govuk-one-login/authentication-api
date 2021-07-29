package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.helpers.TokenGenerator;

import java.io.IOException;
import java.net.HttpCookie;
import java.net.URI;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LogoutIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGOUT_ENDPOINT = "/logout";
    private static final String COOKIE = "Cookie";

    @Test
    public void shouldReturn302AndRedirectToClientLogoutUri() throws JOSEException, IOException {
        String sessionId = "session-id";
        String clientSessionId = "client-session-id";
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        SignedJWT signedJWT =
                TokenGenerator.generateIDToken(
                        "client-id", new Subject(), "http://localhost/issuer", signingKey);
        RedisHelper.createSession(sessionId);
        RedisHelper.addAuthRequestToSession(
                clientSessionId, sessionId, generateAuthRequest().toParameters());
        RedisHelper.addIDTokenToSession(clientSessionId, signedJWT.serialize());
        DynamoHelper.registerClient(
                "client-id",
                "client-name",
                singletonList("http://localhost:8080/redirect"),
                singletonList("client-1"),
                singletonList("openid"),
                "public-key",
                singletonList(
                        "https://di-auth-stub-relying-party-build.london.cloudapps.digital/"));
        Client client = ClientBuilder.newClient();
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add(COOKIE, buildCookieString(sessionId, clientSessionId));
        Response response =
                client.target(ROOT_RESOURCE_URL + LOGOUT_ENDPOINT)
                        .queryParam("id_token_hint", signedJWT.serialize())
                        .queryParam(
                                "post_logout_redirect_uri",
                                "https://di-auth-stub-relying-party-build.london.cloudapps.digital/")
                        .queryParam("state", "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU")
                        .request()
                        .headers(headers)
                        .get();

        assertEquals(302, response.getStatus());
        assertTrue(
                response.getHeaders()
                        .get("Location")
                        .contains(
                                "https://di-auth-stub-relying-party-build.london.cloudapps.digital/?state="
                                        + "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU"));
    }

    private AuthorizationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthorizationRequest.Builder(responseType, new ClientID("test-client"))
                .redirectionURI(URI.create("http://localhost:8080/redirect"))
                .state(state)
                .build();
    }

    private String buildCookieString(String sessionID, String clientSessionID) {
        var cookie = new HttpCookie("gs", sessionID + "." + clientSessionID);
        return cookie.toString();
    }
}
