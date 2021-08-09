package uk.gov.di.authentication.api;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.entity.SessionState;
import uk.gov.di.entity.UpdateProfileRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.helpers.RequestHelper.requestWithSession;
import static uk.gov.di.entity.UpdateProfileType.ADD_PHONE_NUMBER;

public class UpdateProfileIntegrationTest extends IntegrationTestEndpoints {

    private static final String UPDATE_PROFILE_ENDPOINT = "/update-profile";
    private static final String EMAIL_ADDRESS = "test@test.com";

    @Test
    public void shouldCallUpdateProfileEndpointAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.TWO_FACTOR_REQUIRED);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1");

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, "0123456789");

        Response response = requestWithSession(UPDATE_PROFILE_ENDPOINT, request, sessionId);

        assertEquals(200, response.getStatus());
    }
}
