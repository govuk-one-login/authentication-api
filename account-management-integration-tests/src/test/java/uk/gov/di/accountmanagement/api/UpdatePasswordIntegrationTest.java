package uk.gov.di.accountmanagement.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePasswordRequest;
import uk.gov.di.accountmanagement.lambda.UpdatePasswordHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.UPDATE_PASSWORD;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSWORD_UPDATED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdatePasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdatePasswordHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldSendNotificationAndReturn204WhenUpdatingPasswordIsSuccessful() {
        String publicSubjectID = userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(TEST_EMAIL, "password-2")),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        assertNotificationsReceived(
                notificationsQueue, List.of(new NotifyRequest(TEST_EMAIL, PASSWORD_UPDATED)));

        assertEventTypesReceived(auditTopic, List.of(UPDATE_PASSWORD));
    }

    @Test
    void shouldReturn400WhenNewPasswordIsSameAsOldPassword() throws Exception {
        String publicSubjectID = userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(TEST_EMAIL, "password-1")),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                response, hasBody(new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1024)));

        assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToUpdateDifferentAccount() {
        String correctSubjectID = userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        String otherSubjectID =
                userStore.signUp(
                        "other.user@digital.cabinet-office.gov.uk", "password-2", new Subject());

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePasswordRequest(
                                                        TEST_EMAIL, "password-2")),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", otherSubjectID)));

        assertThat(ex.getMessage(), is("Subject ID does not match principalId"));
    }

    @Test
    void shouldThrowExceptionWhenSubjectIdMissing() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePasswordRequest(
                                                        TEST_EMAIL, "password-2")),
                                        Collections.emptyMap(),
                                        Collections.emptyMap()));

        assertThat(ex.getMessage(), is("principalId is missing"));
    }
}
