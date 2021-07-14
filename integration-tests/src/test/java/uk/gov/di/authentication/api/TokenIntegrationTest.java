package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
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

    @Test
    public void shouldCallTokenResourceAndReturn200() throws JOSEException {
        String clientID = "test-id";
        KeyPair keyPair = generateRsaKeyPair();
        setUpDynamo(keyPair, clientID);
        PrivateKey privateKey = keyPair.getPrivate();
        PrivateKeyJWT privateKeyJWT =
                new PrivateKeyJWT(
                        new ClientID(clientID),
                        URI.create(ROOT_RESOURCE_URL + TOKEN_ENDPOINT),
                        JWSAlgorithm.RS256,
                        (RSAPrivateKey) privateKey,
                        null,
                        null);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("grant_type", Collections.singletonList("authorization_code"));
        customParams.put("client_id", Collections.singletonList(clientID));
        customParams.put("code", Collections.singletonList(new AuthorizationCode().toString()));
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
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        DynamoHelper.signUp("joe.bloggs@digital.cabinet-office.gov.uk", "password-1");
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
