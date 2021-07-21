package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.SessionState;
import uk.gov.di.services.ConfigurationService;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AuthorisationIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTHORIZE_ENDPOINT = "/authorize";

    private static final String CLIENT_ID = "test-client";
    private static final KeyPair KEY_PAIR = generateRsaKeyPair();

    private static final ConfigurationService configurationService = new ConfigurationService();

    @BeforeAll
    public static void setup() {
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("localhost"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"));
    }

    @Test
    public void shouldRedirectToLoginWhenNoCookie() {
        Response response = doAuthorisationRequest(Optional.empty());

        assertEquals(302, response.getStatus());
        assertThat(
                response.getHeaders().get("Location").get(0).toString(),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginWhenBadCookie() {
        Response response = doAuthorisationRequest(Optional.of(new Cookie("gs", "this is bad")));

        assertEquals(302, response.getStatus());
        assertThat(
                response.getHeaders().get("Location").get(0).toString(),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginWhenCookieHasUnknownSessionId() {
        Response response = doAuthorisationRequest(Optional.of(new Cookie("gs", "123.456")));

        assertEquals(302, response.getStatus());
        assertThat(
                response.getHeaders().get("Location").get(0).toString(),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginWhenSessionFromCookieIsNotAuthenticated() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.AUTHENTICATION_REQUIRED);

        Response response =
                doAuthorisationRequest(Optional.of(new Cookie("gs", format("%s.456", sessionId))));

        assertEquals(302, response.getStatus());
        assertThat(
                response.getHeaders().get("Location").get(0).toString(),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
    }

    @Test
    public void shouldIssueAuthorisationCodeWhenSessionFromCookieIsAuthenticated()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.AUTHENTICATED);

        Response response =
                doAuthorisationRequest(Optional.of(new Cookie("gs", format("%s.456", sessionId))));

        assertEquals(302, response.getStatus());
        // TODO: Update assertions to reflect code issuance, once we've written that code
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
    }

    private static KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private Response doAuthorisationRequest(Optional<Cookie> cookie) {
        Client client = ClientBuilder.newClient();

        Invocation.Builder builder =
                client.target(ROOT_RESOURCE_URL + AUTHORIZE_ENDPOINT)
                        .queryParam("response_type", "code")
                        .queryParam("redirect_uri", "localhost")
                        .queryParam("state", "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU")
                        .queryParam("client_id", "test-client")
                        .queryParam("scope", "openid")
                        .request();

        cookie.ifPresent(builder::cookie);

        return builder.get();
    }
}
