package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.lambda.MfaHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.MFA_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";
    private String SESSION_ID;

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new MfaHandler(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
        String subjectId = "new-subject";
        SESSION_ID = redis.createUnauthenticatedSessionWithEmail(USER_EMAIL);
        userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject(subjectId));
        userStore.addVerifiedPhoneNumber(USER_EMAIL, USER_PHONE_NUMBER);
    }

    @Test
    void
            shouldReturn204WithExistingRedisCachedCodeAndTriggerVerifyPhoneNotificationTypeWhenResendingVerifyPhoneCode() {
        String mockPreviouslyIssuedPhoneCode =
                redis.generateAndSavePhoneNumberCode(USER_EMAIL, 900L);

        var response =
                makeRequest(
                        Optional.of(new MfaRequest(USER_EMAIL, true)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(MFA_CODE_SENT));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(USER_PHONE_NUMBER));
        assertThat(requests.get(0).getNotificationType(), equalTo(VERIFY_PHONE_NUMBER));
        assertThat(requests.get(0).getCode(), equalTo(mockPreviouslyIssuedPhoneCode));
    }

    @Test
    void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenNotResendingVerifyPhoneCode() {
        var response =
                makeRequest(
                        Optional.of(new MfaRequest(USER_EMAIL, false)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(MFA_CODE_SENT));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(USER_PHONE_NUMBER));
        assertThat(requests.get(0).getNotificationType(), equalTo(MFA_SMS));
    }

    @Test
    void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenResettingPassword() {
        var response =
                makeRequest(
                        Optional.of(
                                new MfaRequest(USER_EMAIL, false, JourneyType.PASSWORD_RESET_MFA)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(MFA_CODE_SENT));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(USER_PHONE_NUMBER));
        assertThat(requests.get(0).getNotificationType(), equalTo(MFA_SMS));
    }

    @Test
    void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenReauthenticating()
            throws Json.JsonException {
        var authenticatedSessionId = redis.createAuthenticatedSessionWithEmail(USER_EMAIL);

        var response =
                makeRequest(
                        Optional.of(
                                new MfaRequest(USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                        constructFrontendHeaders(authenticatedSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(MFA_CODE_SENT));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(USER_PHONE_NUMBER));
        assertThat(requests.get(0).getNotificationType(), equalTo(MFA_SMS));
    }

    @Test
    void shouldReturn4O0WhenRequestingACodeForReauthenticationWhichBreachesTheMaxThreshold()
            throws Json.JsonException {
        var authenticatedSessionId = redis.createAuthenticatedSessionWithEmail(USER_EMAIL);
        redis.incrementSessionCodeRequestCount(
                authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);
        redis.incrementSessionCodeRequestCount(
                authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);
        redis.incrementSessionCodeRequestCount(
                authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);
        redis.incrementSessionCodeRequestCount(
                authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);
        redis.incrementSessionCodeRequestCount(
                authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);

        var response =
                makeRequest(
                        Optional.of(
                                new MfaRequest(USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                        constructFrontendHeaders(authenticatedSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(MFA_INVALID_CODE_REQUEST));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(0));
    }

    @Test
    void shouldReturn400WhenInvalidMFAJourneyCombination() throws Json.JsonException {
        var authenticatedSessionId = redis.createAuthenticatedSessionWithEmail(USER_EMAIL);

        var response =
                makeRequest(
                        Optional.of(new MfaRequest(USER_EMAIL, false, JourneyType.PASSWORD_RESET)),
                        constructFrontendHeaders(authenticatedSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1002));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(0));
    }
}
