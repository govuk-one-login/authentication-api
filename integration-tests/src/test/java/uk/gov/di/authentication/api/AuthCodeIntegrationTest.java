package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;

import java.io.IOException;
import java.net.HttpCookie;
import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthCodeIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTH_CODE_ENDPOINT = "/auth-code";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "test-pass-01";
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String COOKIE = "Cookie";

    @Test
    public void shouldReturn302WithSuccessfullAuthorisationResponse() throws IOException {
        String sessionId = "some-session-id";
        String clientSessionId = "some-client-session-id";
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        RedisHelper.createSession(sessionId);
        RedisHelper.setSessionState(sessionId, SessionState.MFA_CODE_VERIFIED);
        RedisHelper.addAuthRequestToSession(
                clientSessionId, sessionId, generateAuthRequest().toParameters(), EMAIL);
        setUpDynamo(keyPair);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add(COOKIE, buildCookieString(sessionId, clientSessionId));
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + AUTH_CODE_ENDPOINT)
                        .request()
                        .headers(headers)
                        .get();
        assertEquals(302, response.getStatus());
    }

    private AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }

    private void setUpDynamo(KeyPair keyPair) {
        DynamoHelper.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                AuthenticationValues.VERY_HIGH_LEVEL.getValue());
    }

    private String buildCookieString(String sessionID, String clientSessionID) {
        var cookie = new HttpCookie("gs", sessionID + "." + clientSessionID);
        return cookie.toString();
    }
}
