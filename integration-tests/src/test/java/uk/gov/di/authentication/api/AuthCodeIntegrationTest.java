package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
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
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.AuthCodeRequest;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthCodeIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTH_CODE_ENDPOINT = "/auth-code";
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");

    @Test
    public void shouldReturn302WithSuccessfullAuthorisationResponse() throws IOException {
        String sessionId = "some-session-id";
        String clientSessionId = "some-client-session-id";
        AuthCodeRequest authCodeRequest = new AuthCodeRequest(clientSessionId);
        KeyPair keyPair = generateRsaKeyPair();
        RedisHelper.createSession(sessionId, clientSessionId);
        RedisHelper.addAuthRequestToSession(
                clientSessionId, sessionId, generateAuthRequest().toParameters());
        setUpDynamo(keyPair);

        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + AUTH_CODE_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        Response response =
                invocationBuilder
                        .headers(headers)
                        .post(Entity.entity(authCodeRequest, MediaType.APPLICATION_JSON));

        assertEquals(302, response.getStatus());
    }

    private AuthorizationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthorizationRequest.Builder(responseType, CLIENT_ID)
                .redirectionURI(REDIRECT_URI)
                .state(state)
                .build();
    }

    private void setUpDynamo(KeyPair keyPair) {
        DynamoHelper.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList(REDIRECT_URI.toString()),
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
