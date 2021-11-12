package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.BaseFrontendRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.authentication.shared.entity.SessionState;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;

public class UserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String USEREXISTS_ENDPOINT = "/user-exists";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallUserExistsEndpointAndReturnAuthenticationRequestStateWhenUserExists()
            throws IOException {
        String emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        DynamoHelper.signUp(emailAddress, "password-1");
        RedisHelper.setSessionState(sessionId, SessionState.NEW);

        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);
        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL, USEREXISTS_ENDPOINT, request, headers);

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
        assertEquals(AUTHENTICATION_REQUIRED, checkUserExistsResponse.getSessionState());
        assertTrue(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnUserNotFoundStateWhenUserDoesNotExist()
            throws IOException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);
        RedisHelper.setSessionState(sessionId, SessionState.NEW);
        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);
        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL, USEREXISTS_ENDPOINT, request, headers);

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
        assertEquals(USER_NOT_FOUND, checkUserExistsResponse.getSessionState());
        assertFalse(checkUserExistsResponse.doesUserExist());
    }
}
