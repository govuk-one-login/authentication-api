package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.BaseFrontendRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.SessionState;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new CheckUserExistsHandler(configurationService);
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnAuthenticationRequestStateWhenUserExists()
            throws IOException {
        String emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        DynamoHelper.signUp(emailAddress, "password-1");
        RedisHelper.setSessionState(sessionId, SessionState.NEW);

        CheckUserExistsRequest request = new CheckUserExistsRequest(emailAddress);

        var response =
                makeRequest(Optional.of(request), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(200));
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.getEmail(), equalTo(emailAddress));
        assertThat(checkUserExistsResponse.getSessionState(), equalTo(AUTHENTICATION_REQUIRED));
        assertTrue(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnUserNotFoundStateWhenUserDoesNotExist()
            throws IOException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.NEW);
        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);

        var response =
                makeRequest(Optional.of(request), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(200));

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.getEmail(), equalTo(emailAddress));
        assertThat(checkUserExistsResponse.getSessionState(), equalTo(USER_NOT_FOUND));
        assertFalse(checkUserExistsResponse.doesUserExist());
    }
}
