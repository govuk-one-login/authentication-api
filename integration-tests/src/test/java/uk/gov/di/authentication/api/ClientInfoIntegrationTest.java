package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientInfoResponse;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.ServiceType;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClientInfoIntegrationTest extends IntegrationTestEndpoints {

    private static final String CLIENTINFO_ENDPOINT = "/client-info";

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String TEST_CLIENT_NAME = "test-client-name";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldReturn400WhenClientSessionIdMissing() {

        Client client = ClientBuilder.newClient();
        Response response = client.target(ROOT_RESOURCE_URL + CLIENTINFO_ENDPOINT).request().get();
        assertEquals(400, response.getStatus());
    }

    @Test
    public void shouldReturn200AndClientInfoResponseForValidClient() throws IOException {
        String sessionId = RedisHelper.createSession();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        RedisHelper.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("Client-Session-Id", CLIENT_SESSION_ID);

        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + CLIENTINFO_ENDPOINT)
                        .request()
                        .headers(headers)
                        .get();

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        ClientInfoResponse clientInfoResponse =
                objectMapper.readValue(responseString, ClientInfoResponse.class);
        assertEquals(CLIENT_ID, clientInfoResponse.getClientId());
        assertEquals(TEST_CLIENT_NAME, clientInfoResponse.getClientName());
        assertThat(clientInfoResponse.getScopes(), hasItem("openid"));
        assertThat(clientInfoResponse.getScopes(), hasItem("email"));
        assertThat(clientInfoResponse.getScopes(), hasSize(2));
    }

    private void registerClient(KeyPair keyPair) {
        DynamoHelper.registerClient(
                CLIENT_ID,
                TEST_CLIENT_NAME,
                singletonList(REDIRECT_URI),
                singletonList(EMAIL),
                List.of("openid", "email"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY));
    }
}
