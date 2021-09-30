package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.API_KEY;
import static uk.gov.di.authentication.api.IntegrationTestEndpoints.FRONTEND_ROOT_RESOURCE_URL;

public class ResetPasswordIntegrationTest {

    private static final String RESET_PASSWORD_ENDPOINT = "/reset-password";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PASSWORD = "Pa55word";
    private static final String CODE = "0123456789";

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(8888, objectMapper);

    @BeforeEach
    public void setUp() {
        notifyStub.init();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    public void shouldUpdatePasswordAndReturn204() throws JsonProcessingException {
        String subject = "new-subject";
        ResetPasswordWithCodeRequest requestBody = new ResetPasswordWithCodeRequest(CODE, PASSWORD);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1", new Subject(subject));
        RedisHelper.generateAndSavePasswordResetCode(subject, CODE, 900l);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("X-API-Key", API_KEY);
        Response response =
                ClientBuilder.newClient()
                        .target(FRONTEND_ROOT_RESOURCE_URL + RESET_PASSWORD_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(headers)
                        .post(Entity.entity(requestBody, MediaType.APPLICATION_JSON));
        notifyStub.waitForRequest(60);

        assertEquals(204, response.getStatus());
    }
}
