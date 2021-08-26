package uk.gov.di.authentication.api;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KmsHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.ServiceType;

import java.io.IOException;
import java.net.HttpCookie;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LogoutIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGOUT_ENDPOINT = "/logout";
    private static final String COOKIE = "Cookie";
    private static final String BASE_URL = System.getenv().getOrDefault("BASE_URL", "rubbish");

    @Test
    public void shouldReturn302AndRedirectToClientLogoutUri() throws IOException, ParseException {
        Nonce nonce = new Nonce();
        String sessionId = "session-id";
        String clientSessionId = "client-session-id";
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(10);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(BASE_URL),
                        new Subject(),
                        List.of(new Audience("client-id")),
                        expiryDate,
                        new Date());
        idTokenClaims.setNonce(nonce);
        SignedJWT signedJWT = KmsHelper.signIdToken(idTokenClaims.toJWTClaimsSet());
        RedisHelper.createSession(sessionId);
        RedisHelper.addAuthRequestToSession(
                clientSessionId,
                sessionId,
                generateAuthRequest(nonce).toParameters(),
                "joe.bloggs@digital.cabinet-office.gov.uk");
        RedisHelper.addIDTokenToSession(clientSessionId, signedJWT.serialize());
        DynamoHelper.registerClient(
                "client-id",
                "client-name",
                singletonList("http://localhost:8080/redirect"),
                singletonList("client-1"),
                singletonList("openid"),
                "public-key",
                singletonList("https://di-auth-stub-relying-party-build.london.cloudapps.digital/"),
                String.valueOf(ServiceType.MANDATORY));
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
                        .property(ClientProperties.FOLLOW_REDIRECTS, Boolean.FALSE)
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

    private AuthenticationRequest generateAuthRequest(Nonce nonce) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        responseType,
                        scope,
                        new ClientID("test-client"),
                        URI.create("http://localhost:8080/redirect"))
                .state(state)
                .nonce(nonce)
                .build();
    }

    private String buildCookieString(String sessionID, String clientSessionID) {
        var cookie = new HttpCookie("gs", sessionID + "." + clientSessionID);
        return cookie.toString();
    }
}
