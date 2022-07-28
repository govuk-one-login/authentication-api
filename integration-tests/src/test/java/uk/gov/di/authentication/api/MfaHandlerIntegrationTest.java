package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.lambda.MfaHandler;
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
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";
    private String SESSION_ID;

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new MfaHandler(TEST_CONFIGURATION_SERVICE);
        String subjectId = "new-subject";
        SESSION_ID = redis.createUnauthenticatedSessionWithEmail(USER_EMAIL);
        userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject(subjectId));
        userStore.addPhoneNumber(USER_EMAIL, USER_PHONE_NUMBER);
    }

    @Test
    void
            shouldReturn204WithExistingRedisCachedCodeAndTriggerVerifyPhoneNotificationTypeWhenResendingVerifyPhoneCode() {
        String mockPreviouslyIssuedPhoneCode =
                redis.generateAndSavePhoneNumberCode(USER_EMAIL, 900l);

        var response =
                makeRequest(
                        Optional.of(new MfaRequest(USER_EMAIL, true)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertEventTypesReceived(auditTopic, List.of(MFA_CODE_SENT));

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
        assertEventTypesReceived(auditTopic, List.of(MFA_CODE_SENT));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(USER_PHONE_NUMBER));
        assertThat(requests.get(0).getNotificationType(), equalTo(MFA_SMS));
    }
}
