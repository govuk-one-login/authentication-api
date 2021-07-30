package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

    @Test
    public void shouldCallTokenResourceAndReturn200() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        setUpDynamo(keyPair, CLIENT_ID);
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
        customParams.put("redirect_uri", Collections.singletonList("http://localhost/redirect"));
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

    private void setUpDynamo(KeyPair keyPair, String clientID) {
        DynamoHelper.registerClient(
                clientID,
                "test-client",
                singletonList("http://localhost/redirect"),
                singletonList(TEST_EMAIL),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-logout-redirect"));
        DynamoHelper.signUp(TEST_EMAIL, "password-1");
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

    private AuthorizationRequest generateAuthRequest() {
        Scope scopeValues = new Scope();
        scopeValues.add("openid");
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthorizationRequest.Builder(responseType, new ClientID(CLIENT_ID))
                .redirectionURI(URI.create("http://localhost/redirect"))
                .state(state)
                .scope(scopeValues)
                .build();
    }
}
