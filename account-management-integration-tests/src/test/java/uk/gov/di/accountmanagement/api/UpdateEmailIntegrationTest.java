package uk.gov.di.accountmanagement.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.lambda.UpdateEmailHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.UPDATE_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateEmailIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdateEmailHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldCallUpdateEmailEndpointAndReturn204WhenUpdatingEmailIsSuccessful() {
        String publicSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);
        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, otp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        assertNotificationsReceived(
                notificationsQueue, List.of(new NotifyRequest(NEW_EMAIL_ADDRESS, EMAIL_UPDATED)));

        assertEventTypesReceived(auditTopic, List.of(UPDATE_EMAIL));
    }

    @Test
    void shouldReturn400WhenOtpIsInvalid() throws Exception {
        String publicSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String realOtp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);
        String badOtp = "This is not the correct OTP";

        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, badOtp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                response, hasBody(new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1020)));

        assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturn400WhenNewEmailIsMalformed() {
        String badEmailAddress = "This is not a valid email address";
        String publicSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);

        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, badEmailAddress, otp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));

        assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturn400WhenNewEmailIsAlreadyTaken() throws Exception {
        String publicSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        userStore.signUp(NEW_EMAIL_ADDRESS, "password-2", new Subject());
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);

        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, otp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                response, hasBody(new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1009)));

        assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToUpdateDifferentAccount() {
        String correctSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otherSubjectID =
                userStore.signUp(
                        "other.user@digital.cabinet-office.gov.uk", "password-2", new Subject());
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdateEmailRequest(
                                                        EXISTING_EMAIL_ADDRESS,
                                                        NEW_EMAIL_ADDRESS,
                                                        otp)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", otherSubjectID)));

        assertThat(ex.getMessage(), is("Subject ID does not match principalId"));
    }

    @Test
    void shouldThrowExceptionWhenSubjectIdMissing() {
        userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdateEmailRequest(
                                                        EXISTING_EMAIL_ADDRESS,
                                                        NEW_EMAIL_ADDRESS,
                                                        otp)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap()));

        assertThat(ex.getMessage(), is("principalId is missing"));
    }
}
