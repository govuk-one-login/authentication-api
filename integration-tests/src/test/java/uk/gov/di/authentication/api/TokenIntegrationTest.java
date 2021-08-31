package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.ServiceType;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenIntegrationTest extends IntegrationTestEndpoints {

    private static final String TOKEN_ENDPOINT = "/token";
    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String CLIENT_ID = "test-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";

    @Test
    public void shouldCallTokenResourceAndReturn200() throws JOSEException {
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        setUpDynamo(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PrivateKeyJWT privateKeyJWT =
                new PrivateKeyJWT(
                        new ClientID(CLIENT_ID),
                        URI.create(ROOT_RESOURCE_URL + TOKEN_ENDPOINT),
                        JWSAlgorithm.RS256,
                        (RSAPrivateKey) privateKey,
                        null,
                        null);
        String code = new AuthorizationCode().toString();
        RedisHelper.addAuthCodeAndCreateClientSession(
                code, "a-client-session-id", TEST_EMAIL, generateAuthRequest().toParameters());
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("grant_type", Collections.singletonList("authorization_code"));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(code));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + TOKEN_ENDPOINT);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.TEXT_PLAIN);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        Response response =
                invocationBuilder.post(Entity.entity(requestParams, MediaType.TEXT_PLAIN));

        assertEquals(200, response.getStatus());
    }

    private void setUpDynamo(KeyPair keyPair) {
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList(REDIRECT_URI),
                singletonList(TEST_EMAIL),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-logout-redirect"),
                String.valueOf(ServiceType.MANDATORY));
        DynamoHelper.signUp(TEST_EMAIL, "password-1");
    }

    private AuthenticationRequest generateAuthRequest() {
        Scope scopeValues = new Scope();
        scopeValues.add("openid");
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Nonce nonce = new Nonce();
        return new AuthenticationRequest.Builder(
                        responseType,
                        scopeValues,
                        new ClientID(CLIENT_ID),
                        URI.create("http://localhost/redirect"))
                .state(state)
                .nonce(nonce)
                .build();
    }
}
