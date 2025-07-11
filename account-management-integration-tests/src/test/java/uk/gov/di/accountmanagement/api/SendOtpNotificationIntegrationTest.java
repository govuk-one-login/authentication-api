package uk.gov.di.accountmanagement.api;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.SendNotificationRequest;
import uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler;
import uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_PHONE_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_SEND_OTP;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SendOtpNotificationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String TEST_NEW_EMAIL = "new.joe@digital.cabinet-office.gov.uk";
    private static final String TEST_TESTER_CLIENT_ID = "tester-client-id";
    private static final String TEST_PHONE_NUMBER =
            Long.toString(
                    PhoneNumberUtil.getInstance()
                            .getExampleNumberForType("GB", MOBILE)
                            .getNationalNumber());

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @BeforeEach
    void setup() {
        handler = new SendOtpNotificationHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Nested
    class EmailVerification {

        @Nested
        class UserReceivesVerificationEmail {
            @Test
            void shouldSendNotificationAndReturn204ForVerifyEmailRequest() {
                userStore.signUp(TEST_EMAIL, "password");

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                TEST_NEW_EMAIL, VERIFY_EMAIL, TEST_PHONE_NUMBER)),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

                NotificationAssertionHelper.assertNotificationsReceived(
                        notificationsQueue,
                        List.of(
                                new NotifyRequest(
                                        TEST_NEW_EMAIL, VERIFY_EMAIL, SupportedLanguage.EN)));

                List<String> receivedEvents =
                        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_SEND_OTP));
                AuditEventExpectation expectation = new AuditEventExpectation(AUTH_SEND_OTP.name());
                expectation.withAttribute("extensions.notification-type", VERIFY_EMAIL.name());
                expectation.withAttribute("extensions.test-user", false);
                expectation.verify(receivedEvents);
            }
        }

        @Nested
        class EmailAlreadyInUseErrors {
            @Test
            void shouldReturn400ForVerifyEmailRequestWhenUserAlreadyExists() throws Exception {
                String password = "password-1";
                userStore.signUp(TEST_EMAIL, password);

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                TEST_EMAIL, VERIFY_EMAIL, TEST_PHONE_NUMBER)),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
                assertThat(
                        response,
                        hasBody(objectMapper.writeValueAsString(ErrorResponse.ACCT_WITH_EMAIL_EXISTS)));

                assertNoNotificationsReceived(notificationsQueue);
                assertNoTxmaAuditEventsReceived(txmaAuditQueue);
            }
        }
    }

    @Nested
    class PhoneNumberVerification {

        @Nested
        class UserReceivesVerificationSms {
            @Test
            void shouldSendNotificationAndReturn204ForVerifyPhoneNumberRequest() {
                String password = "password-1";
                userStore.signUp(TEST_EMAIL, password);

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                TEST_EMAIL,
                                                VERIFY_PHONE_NUMBER,
                                                TEST_PHONE_NUMBER)),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

                NotificationAssertionHelper.assertNotificationsReceived(
                        notificationsQueue,
                        List.of(
                                new NotifyRequest(
                                        TEST_PHONE_NUMBER,
                                        VERIFY_PHONE_NUMBER,
                                        SupportedLanguage.EN)));

                List<String> receivedEvents =
                        assertTxmaAuditEventsReceived(
                                txmaAuditQueue, List.of(AUTH_SEND_OTP, AUTH_PHONE_CODE_SENT));
                AuditEventExpectation sendOtpExpectation =
                        new AuditEventExpectation(AUTH_SEND_OTP.name());
                sendOtpExpectation.withAttribute(
                        "extensions.notification-type", VERIFY_PHONE_NUMBER.name());
                sendOtpExpectation.withAttribute("extensions.test-user", false);
                sendOtpExpectation.verify(receivedEvents);

                AuditEventExpectation phoneCodeSentExpectation =
                        new AuditEventExpectation(AUTH_PHONE_CODE_SENT.name());
                phoneCodeSentExpectation.withAttribute(
                        "extensions." + AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                        ACCOUNT_MANAGEMENT.name());
                phoneCodeSentExpectation.withAttribute(
                        "extensions." + AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                        DEFAULT.name().toLowerCase());
                phoneCodeSentExpectation.verify(receivedEvents);
            }
        }

        @Nested
        class PhoneNumberValidationErrors {
            @Test
            void smsNotSentForUnknownUsers() {
                var nonExistentUserEmail = "i.do.not.exist@digital.cabinet-office.gov.uk";

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                nonExistentUserEmail,
                                                VERIFY_PHONE_NUMBER,
                                                TEST_PHONE_NUMBER)),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
                assertNoNotificationsReceived(notificationsQueue);
                assertNoTxmaAuditEventsReceived(txmaAuditQueue);
            }

            @Test
            void shouldReturn400WhenPhoneNumberIsInvalid() throws Json.JsonException {
                String password = "password-1";
                userStore.signUp(TEST_EMAIL, password);
                String badPhoneNumber = "This is not a valid phone number";

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                TEST_EMAIL, VERIFY_PHONE_NUMBER, badPhoneNumber)),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
                assertThat(
                        response,
                        hasBody(
                                objectMapper.writeValueAsString(
                                        ErrorResponse.INVALID_PHONE_NUMBER)));

                assertNoNotificationsReceived(notificationsQueue);
                assertNoTxmaAuditEventsReceived(txmaAuditQueue);
            }

            @Test
            void shouldReturn400WhenNewPhoneNumberIsTheSameAsCurrentPhoneNumber()
                    throws Json.JsonException {
                userStore.signUp(TEST_EMAIL, "password");
                userStore.addVerifiedPhoneNumber(TEST_EMAIL, "+447755551084");

                Map<String, String> headers = new HashMap<>();
                headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

                var response =
                        makeRequest(
                                Optional.of(
                                        new SendNotificationRequest(
                                                TEST_EMAIL, VERIFY_PHONE_NUMBER, "+447755551084")),
                                headers,
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.of("clientId", TEST_TESTER_CLIENT_ID));

                assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
                assertThat(
                        response,
                        hasBody(
                                objectMapper.writeValueAsString(
                                        ErrorResponse.NEW_PHONE_NUMBER_ALREADY_IN_USE)));

                assertNoNotificationsReceived(notificationsQueue);
                assertNoTxmaAuditEventsReceived(txmaAuditQueue);
            }
        }
    }
}
