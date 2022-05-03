package uk.gov.di.accountmanagement.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.SendNotificationRequest;
import uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler;
import uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.SEND_OTP;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SendOtpNotificationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER =
            Long.toString(
                    PhoneNumberUtil.getInstance()
                            .getExampleNumberForType("GB", MOBILE)
                            .getNationalNumber());

    @BeforeEach
    void setup() {
        handler = new SendOtpNotificationHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldSendNotificationAndReturn204ForVerifyEmailRequest() {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_EMAIL, TEST_PHONE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue, List.of(new NotifyRequest(TEST_EMAIL, VERIFY_EMAIL)));

        assertEventTypesReceived(auditTopic, List.of(SEND_OTP));
    }

    @Test
    void shouldReturn400ForVerifyEmailRequestWhenUserAlreadyExists() throws Exception {
        String password = "password-1";
        userStore.signUp(TEST_EMAIL, password);

        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_EMAIL, TEST_PHONE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1009)));

        NotificationAssertionHelper.assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldSendNotificationAndReturn204ForVerifyPhoneNumberRequest() {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER)));

        assertEventTypesReceived(auditTopic, List.of(SEND_OTP));
    }

    @Test
    void shouldReturn204ForVerifyPhoneNumberRequestWhenUserDoesNotExist() {
        var nonExistentUserEmail = "i.do.not.exist@digital.cabinet-office.gov.uk";

        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        nonExistentUserEmail,
                                        VERIFY_PHONE_NUMBER,
                                        TEST_PHONE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER)));

        assertEventTypesReceived(auditTopic, List.of(SEND_OTP));
    }

    @Test
    void shouldReturn400WhenPhoneNumberIsInvalid() throws JsonProcessingException {
        String badPhoneNumber = "This is not a valid phone number";

        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_PHONE_NUMBER, badPhoneNumber)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1012)));

        NotificationAssertionHelper.assertNoNotificationsReceived(notificationsQueue);

        assertNoAuditEventsReceived(auditTopic);
    }
}
