package uk.gov.di.authentication.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_SENT;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@Disabled
public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(19999, ObjectMapperFactory.getInstance());

    @BeforeEach
    public void setUp() {
        handler = new ResetPasswordRequestHandler(configurationService);
        notifyStub.init();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200() throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, email);
        RedisHelper.setSessionState(sessionId, AUTHENTICATION_REQUIRED);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.of(new ResetPasswordRequest(email)), headers, Map.of());
        notifyStub.waitForRequest(60);

        assertThat(response, hasStatus(200));

        BaseAPIResponse resetPasswordResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(resetPasswordResponse.getSessionState(), equalTo(RESET_PASSWORD_LINK_SENT));
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn400WhenInvalidState() throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, email);
        RedisHelper.setSessionState(sessionId, NEW);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.of(new ResetPasswordRequest(email)), headers, Map.of());

        assertThat(response, hasStatus(400));
    }
}
