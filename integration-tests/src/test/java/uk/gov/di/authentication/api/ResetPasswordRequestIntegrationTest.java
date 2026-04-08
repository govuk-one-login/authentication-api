package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String SECTOR_IDENTIFIER_HOST = "test.com";

    private CodeStorageService codeStorageService;

    @BeforeEach
    void setUp() {
        handler =
                new ResetPasswordRequestHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        codeStorageService =
                new CodeStorageService(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        notificationsQueue.clear();
        txmaAuditQueue.clear();
    }

    @Test
    void shouldCallResetPasswordEndpointAndReturn200ForCodeFlowRequest() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(email));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD_WITH_CODE));
        assertThat(requests.get(0).getCode(), hasLength(6));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, Collections.singletonList(AUTH_PASSWORD_RESET_REQUESTED));
    }

    @Test
    void shouldReturn400WhenUserExceedsMaxPasswordResetRequests() {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);

        // Make multiple requests to exceed the limit (default is 6)
        for (int i = 0; i < 7; i++) {
            var response =
                    makeRequest(
                            Optional.of(new ResetPasswordRequest(email)),
                            constructFrontendHeaders(
                                    sessionId, clientSessionId, persistentSessionId),
                            Map.of());

            // After 6 requests, should start getting blocked
            if (i >= 6) {
                assertThat(response, hasStatus(400));
                assertThat(response, hasJsonBody(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST));
                return;
            }
        }
    }

    @Test
    void shouldReturn400WhenUserIsBlockedFromRequestingPasswordResets() {
        String email = "joe.bloggs+5@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);

        // Block user from requesting password resets
        codeStorageService.saveBlockedForEmail(
                email, "code-request-blocked:EMAIL_PASSWORD_RESET", 900);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(0));
    }

    @Test
    void shouldReturn400WhenUserIsBlockedFromEnteringInvalidPasswordResetCodes() {
        String email = "joe.bloggs+6@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);

        // Block user from entering invalid codes
        codeStorageService.saveBlockedForEmail(email, "code-blocked:EMAIL_PASSWORD_RESET", 900);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(0));
    }

    @Test
    void shouldReturn400WhenSessionIdMissing() {
        String email = "joe.bloggs+7@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, password);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        // Don't add email to session
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
    }

    @Test
    void shouldReturn400WhenEmailMismatchWithSession() {
        String email = "joe.bloggs+8@digital.cabinet-office.gov.uk";
        String differentEmail = "different@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, password);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(differentEmail)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
    }

    @Test
    void shouldReturn400WhenUserExceedsMaxPasswordResetRequestsOnSixthRequest() {
        String email = "joe.bloggs+9@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);

        // Make exactly 6 requests - the 6th should return TOO_MANY_PW_RESET_REQUESTS
        for (int i = 0; i < 6; i++) {
            var response =
                    makeRequest(
                            Optional.of(new ResetPasswordRequest(email)),
                            constructFrontendHeaders(
                                    sessionId, clientSessionId, persistentSessionId),
                            Map.of());

            if (i < 5) {
                assertThat(response, hasStatus(200));
            } else {
                // 6th request should return TOO_MANY_PW_RESET_REQUESTS
                assertThat(response, hasStatus(400));
                assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_PW_RESET_REQUESTS));
            }
        }
    }
}
