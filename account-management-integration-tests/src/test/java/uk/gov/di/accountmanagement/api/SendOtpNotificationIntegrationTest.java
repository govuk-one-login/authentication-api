package uk.gov.di.accountmanagement.api;

import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.SendNotificationRequest;
import uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler;
import uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.SEND_OTP;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SendOtpNotificationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = buildTestEmail(3);
    private static final String TEST_TESTER_CLIENT_ID = "tester-client-id";

    @BeforeEach
    void setup() {
        handler = new SendOtpNotificationHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldSendNotificationAndReturn204ForVerifyEmailRequest() {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_EMAIL, UK_MOBILE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(TEST_EMAIL, VERIFY_EMAIL, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(txmaAuditQueue, List.of(SEND_OTP));
    }

    @Test
    void shouldReturn400ForVerifyEmailRequestWhenUserAlreadyExists() throws Exception {
        userStore.signUp(TEST_EMAIL, PASSWORD);

        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_EMAIL, UK_MOBILE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1009)));

        NotificationAssertionHelper.assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldSendNotificationAndReturn204ForVerifyPhoneNumberRequest() {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_PHONE_NUMBER, UK_MOBILE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(
                        new NotifyRequest(
                                UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(txmaAuditQueue, List.of(SEND_OTP));
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
                                        UK_MOBILE_NUMBER)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(
                        new NotifyRequest(
                                UK_MOBILE_NUMBER, VERIFY_PHONE_NUMBER, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(txmaAuditQueue, List.of(SEND_OTP));
    }

    @Test
    void shouldReturn400WhenPhoneNumberIsInvalid() throws Json.JsonException {
        String badPhoneNumber = "This is not a valid phone number";

        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_PHONE_NUMBER, badPhoneNumber)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1012)));

        NotificationAssertionHelper.assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldReturn400WhenNewPhoneNumberIsTheSameAsCurrentPhoneNumber()
            throws Json.JsonException {
        userStore.signUp(TEST_EMAIL, PASSWORD);
        userStore.addVerifiedPhoneNumber(TEST_EMAIL, UK_MOBILE_NUMBER);
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        TEST_EMAIL, VERIFY_PHONE_NUMBER, UK_MOBILE_NUMBER_NO_CC)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("clientId", TEST_TESTER_CLIENT_ID));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1044)));

        NotificationAssertionHelper.assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }
}
