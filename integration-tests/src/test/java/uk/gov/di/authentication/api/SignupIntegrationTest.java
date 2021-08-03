package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.SignupRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;

public class SignupIntegrationTest extends IntegrationTestEndpoints {

    private static final String SIGNUP_ENDPOINT = "/signup";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallSignupEndpointAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();

        RedisHelper.setSessionState(sessionId, EMAIL_CODE_VERIFIED);

        SignupRequest request =
                new SignupRequest("joe.bloggs+5@digital.cabinet-office.gov.uk", "password-1");

        Response response = RequestHelper.requestWithSession(SIGNUP_ENDPOINT, request, sessionId);

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        BaseAPIResponse BaseAPIResponse =
                objectMapper.readValue(responseString, BaseAPIResponse.class);
        assertEquals(TWO_FACTOR_REQUIRED, BaseAPIResponse.getSessionState());
        assertTrue(DynamoHelper.userExists("joe.bloggs+5@digital.cabinet-office.gov.uk"));
    }
}
