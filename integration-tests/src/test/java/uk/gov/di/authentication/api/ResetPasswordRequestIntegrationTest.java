package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_SENT;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    public void setUp() {
        handler = new ResetPasswordRequestHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200() throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addPhoneNumber(email, phoneNumber);
        String sessionId = redis.createSession();
        String persistentSessionId = "test-persistent-id";
        redis.addEmailToSession(sessionId, email);
        redis.setSessionState(sessionId, AUTHENTICATION_REQUIRED);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, null, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(email));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD));
        assertTrue(
                requests.get(0).getCode().startsWith("http://localhost:3000/reset-password?code="));

        String[] resetLinkSplit = requests.get(0).getCode().split("\\.");

        assertThat(resetLinkSplit.length, equalTo(4));
        assertThat(resetLinkSplit[2], equalTo(sessionId));
        assertThat(resetLinkSplit[3], equalTo(persistentSessionId));

        BaseAPIResponse resetPasswordResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(resetPasswordResponse.getSessionState(), equalTo(RESET_PASSWORD_LINK_SENT));

        AuditAssertionsHelper.assertEventTypesReceived(
                auditTopic, List.of(PASSWORD_RESET_REQUESTED));
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn400WhenInvalidState() throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addPhoneNumber(email, phoneNumber);
        String sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, email);
        redis.setSessionState(sessionId, NEW);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(0));

        AuditAssertionsHelper.assertEventTypesReceived(
                auditTopic, List.of(PASSWORD_RESET_REQUESTED));
    }
}
