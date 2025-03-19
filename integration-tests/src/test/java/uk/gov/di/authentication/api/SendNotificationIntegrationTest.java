package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.frontendapi.lambda.SendNotificationHandler;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SendNotificationIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private String SESSION_ID;

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    private static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() throws Json.JsonException {
        txmaAuditQueue.clear();
        handler =
                new SendNotificationHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        SESSION_ID = redis.createUnauthenticatedSessionWithEmail(USER_EMAIL);
        authSessionExtension.addSession(SESSION_ID);
        authSessionStore.addEmailToSession(SESSION_ID, USER_EMAIL);
    }

    @Test
    void shouldCallSendNotificationEndpointAndPlaceSuccessMessageOnAuditQueueWhenSuccessful()
            throws Json.JsonException {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        USER_EMAIL,
                                        NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                                        JourneyType.ACCOUNT_RECOVERY)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        var session = redis.getSession(SESSION_ID);
        var authSession = authSessionExtension.getSession(SESSION_ID).orElseThrow();
        assertThat(
                session.getCodeRequestCount(
                        NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        JourneyType.ACCOUNT_RECOVERY),
                equalTo(1));

        assertThat(
                authSession.getCodeRequestCount(
                        NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        JourneyType.ACCOUNT_RECOVERY),
                equalTo(1));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT));
    }
}
