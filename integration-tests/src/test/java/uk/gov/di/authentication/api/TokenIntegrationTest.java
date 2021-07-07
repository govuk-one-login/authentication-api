package uk.gov.di.authentication.api;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenIntegrationTest extends IntegrationTestEndpoints {

    private static final String TOKEN_ENDPOINT = "/token";

    @Test
    public void shouldCallTokenResourceAndReturn200() {
        String clientID = "test-id";
        Client client = ClientBuilder.newClient();
        DynamoHelper.registerClient(
                clientID,
                "test-client",
                singletonList("http://localhost/redirect"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                singletonList("openid"),
                "public-key");
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + TOKEN_ENDPOINT);
        DynamoHelper.signUp("joe.bloggs@digital.cabinet-office.gov.uk", "password-1");
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.TEXT_PLAIN);
        Response response =
                invocationBuilder.post(
                        Entity.entity(
                                format("code=123456789&client_id=%s", clientID),
                                MediaType.TEXT_PLAIN));

        assertEquals(200, response.getStatus());
    }
}
