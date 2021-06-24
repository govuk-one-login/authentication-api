package uk.gov.di.authentication.api;

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
import uk.gov.di.authentication.helpers.SessionHelper;
import uk.gov.di.entity.NotificationType;
import uk.gov.di.entity.VerifyCodeRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.api.AuthorizationAPIResourceIntegrationTest.ROOT_RESOURCE_URL;

public class VerifyCodeIntegrationTest {

    private static final String VERIFY_CODE_ENDPOINT = "/verify-code";

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyEmailAndReturn200() throws IOException {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + VERIFY_CODE_ENDPOINT);
        String sessionId = SessionHelper.createSession();
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);

        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, "123456");

        Response response =
                invocationBuilder
                        .headers(headers)
                        .post(Entity.entity(codeRequest, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());
    }
}
