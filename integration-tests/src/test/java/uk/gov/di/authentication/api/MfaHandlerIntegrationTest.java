package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.lambda.MfaHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.InternationalSmsSendCountExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_MFA_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final int INTERNATIONAL_SMS_SEND_LIMIT = 3;
    private String SESSION_ID;

    @RegisterExtension
    protected static final InternationalSmsSendCountExtension internationalSmsSendCountStore =
            new InternationalSmsSendCountExtension(INTERNATIONAL_SMS_SEND_LIMIT);

    @BeforeEach
    void setup() {
        handler = new MfaHandler(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Nested
    class WhenAUsersMfaMethodsHaveNotBeenMigrated {
        private static final String USER_PHONE_NUMBER = "+447712345432";

        @BeforeEach
        void setup() throws Json.JsonException {
            SESSION_ID = IdGenerator.generate();
            authSessionStore.addSession(SESSION_ID);
            authSessionStore.addEmailToSession(SESSION_ID, USER_EMAIL);
            userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject("new-subject"));
            userStore.addVerifiedPhoneNumber(USER_EMAIL, USER_PHONE_NUMBER);
        }

        @Test
        void
                shouldReturn204WithExistingRedisCachedCodeAndTriggerVerifyPhoneNotificationTypeWhenResendingVerifyPhoneCode() {
            String previouslyIssuedPhoneCode =
                    redis.generateAndSavePhoneNumberCode(
                            USER_EMAIL.concat(USER_PHONE_NUMBER), 900L);

            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, true)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationNotificationTypeAndCode(
                    notificationsQueue,
                    USER_PHONE_NUMBER,
                    VERIFY_PHONE_NUMBER,
                    previouslyIssuedPhoneCode);
        }

        @Test
        void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenNotResendingVerifyPhoneCode() {
            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, false)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));

            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, USER_PHONE_NUMBER, MFA_SMS);
        }

        @Test
        void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenResettingPassword() {
            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.PASSWORD_RESET_MFA)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, USER_PHONE_NUMBER, MFA_SMS);
        }

        @Test
        void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenReauthenticating()
                throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);
            authSessionStore.addEmailToSession(authenticatedSessionId, USER_EMAIL);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, USER_PHONE_NUMBER, MFA_SMS);
        }

        @Test
        void shouldReturn400WhenInvalidMFAJourneyCombination() throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(USER_EMAIL, false, JourneyType.PASSWORD_RESET)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_NOTIFICATION_TYPE));

            List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
            assertThat(requests, hasSize(0));
        }

        @Test
        void shouldReturn400WhenRequestingACodeForReauthenticationWhichBreachesTheMaxThreshold()
                throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);

            aUserHasEnteredAnOTPIncorrectlyTheMaximumAllowedTimes(authenticatedSessionId);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_MFA_OTPS_SENT));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_INVALID_CODE_REQUEST));

            List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
            assertThat(requests, hasSize(0));
        }
    }

    @Nested
    class WhenAUsersMfaMethodsHaveBeenMigrated {
        private static final String MIGRATED_PHONE_NUMBER_1 = "+447900000001";
        private static final String MIGRATED_PHONE_NUMBER_2 = "+447900000002";
        private static final MFAMethod DEFAULT_SMS_METHOD =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        MIGRATED_PHONE_NUMBER_1,
                        PriorityIdentifier.DEFAULT,
                        "mfa-id-1");
        private static final MFAMethod BACKUP_SMS_METHOD =
                MFAMethod.smsMfaMethod(
                        true, true, MIGRATED_PHONE_NUMBER_2, PriorityIdentifier.BACKUP, "mfa-id-2");

        @BeforeEach
        void setup() throws Json.JsonException {
            SESSION_ID = IdGenerator.generate();
            authSessionStore.addSession(SESSION_ID);
            authSessionStore.addEmailToSession(SESSION_ID, USER_EMAIL);
            userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject("new-subject"));
            userStore.setMfaMethodsMigrated(USER_EMAIL, true);

            userStore.addMfaMethodSupportingMultiple(USER_EMAIL, DEFAULT_SMS_METHOD);
            userStore.addMfaMethodSupportingMultiple(USER_EMAIL, BACKUP_SMS_METHOD);
        }

        @Test
        void shouldReturn204AndSendCodeToCorrectNumberWhenUsersMfaMethodsHaveBeenMigrated() {
            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, false)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, MIGRATED_PHONE_NUMBER_1, MFA_SMS);
        }

        @Test
        void shouldReturn204AndSendCodeToCorrectNumberWhenIdentifiedMfaMethodIsChosen() {
            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL,
                                            false,
                                            null,
                                            BACKUP_SMS_METHOD.getMfaIdentifier())),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, MIGRATED_PHONE_NUMBER_2, MFA_SMS);
        }

        @Test
        void
                shouldReturn204WithExistingRedisCachedCodeAndTriggerVerifyPhoneNotificationTypeWhenResendingVerifyPhoneCode() {
            String previouslyIssuedPhoneCode =
                    redis.generateAndSavePhoneNumberCode(
                            USER_EMAIL.concat(MIGRATED_PHONE_NUMBER_1), 900L);

            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, true)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationNotificationTypeAndCode(
                    notificationsQueue,
                    MIGRATED_PHONE_NUMBER_1,
                    VERIFY_PHONE_NUMBER,
                    previouslyIssuedPhoneCode);
        }

        @Test
        void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenResettingPassword() {
            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.PASSWORD_RESET_MFA)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, MIGRATED_PHONE_NUMBER_1, MFA_SMS);
        }

        @Test
        void shouldReturn204AndTriggerMfaSmsNotificationTypeWhenReauthenticating()
                throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);
            authSessionStore.addEmailToSession(authenticatedSessionId, USER_EMAIL);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
            assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
                    notificationsQueue, MIGRATED_PHONE_NUMBER_1, MFA_SMS);
        }

        @Test
        void shouldReturn400WhenInvalidMFAJourneyCombination() throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(USER_EMAIL, false, JourneyType.PASSWORD_RESET)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_NOTIFICATION_TYPE));

            List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
            assertThat(requests, hasSize(0));
        }

        @Test
        void shouldReturn400WhenRequestingACodeForReauthenticationWhichBreachesTheMaxThreshold()
                throws Json.JsonException {
            var authenticatedSessionId = IdGenerator.generate();
            authSessionStore.addSession(authenticatedSessionId);

            aUserHasEnteredAnOTPIncorrectlyTheMaximumAllowedTimes(authenticatedSessionId);

            var response =
                    makeRequest(
                            Optional.of(
                                    new MfaRequest(
                                            USER_EMAIL, false, JourneyType.REAUTHENTICATION)),
                            constructFrontendHeaders(authenticatedSessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_MFA_OTPS_SENT));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_INVALID_CODE_REQUEST));

            List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
            assertThat(requests, hasSize(0));
        }
    }

    @Nested
    class InternationalSmsSendLimitTests {
        private static final ConfigurationService TXMA_WITH_INT_SMS_LIMIT_CONFIG =
                new IntegrationTestConfigurationService(
                        notificationsQueue,
                        tokenSigner,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters) {
                    @Override
                    public String getTxmaAuditQueueUrl() {
                        return txmaAuditQueue.getQueueUrl();
                    }

                    @Override
                    public int getInternationalSmsNumberSendLimit() {
                        return INTERNATIONAL_SMS_SEND_LIMIT;
                    }
                };

        private static final String INTERNATIONAL_PHONE_NUMBER = "+33612345678";

        @BeforeEach
        void setup() throws Json.JsonException {
            SESSION_ID = IdGenerator.generate();
            authSessionStore.addSession(SESSION_ID);
            authSessionStore.addEmailToSession(SESSION_ID, USER_EMAIL);
            userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject("new-subject"));
            handler = new MfaHandler(TXMA_WITH_INT_SMS_LIMIT_CONFIG, redisConnectionService);
        }

        @Test
        void shouldReturn400WhenInternationalNumberHasHitLimit() throws Json.JsonException {
            userStore.addVerifiedPhoneNumber(USER_EMAIL, INTERNATIONAL_PHONE_NUMBER);

            for (int i = 0; i < INTERNATIONAL_SMS_SEND_LIMIT; i++) {
                internationalSmsSendCountStore.recordSmsSent(INTERNATIONAL_PHONE_NUMBER);
            }

            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, false)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS));
        }

        @Test
        void shouldReturn204WhenInternationalNumberIsBelowLimit() {
            userStore.addVerifiedPhoneNumber(USER_EMAIL, INTERNATIONAL_PHONE_NUMBER);

            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, false)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
        }

        @Test
        void shouldReturn204ForDomesticNumberRegardlessOfLimit() {
            String domesticNumber = "+447712345432";
            userStore.addVerifiedPhoneNumber(USER_EMAIL, domesticNumber);

            var response =
                    makeRequest(
                            Optional.of(new MfaRequest(USER_EMAIL, false)),
                            constructFrontendHeaders(SESSION_ID),
                            Map.of());

            assertThat(response, hasStatus(204));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_MFA_CODE_SENT));
        }
    }

    private static void assertNotificationsQueueHasMessageWithDestinationAndNotificationType(
            SqsQueueExtension notificationsQueue,
            String expectedDestination,
            NotificationType expectedNotificationType) {
        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(expectedDestination));
        assertThat(requests.get(0).getNotificationType(), equalTo(expectedNotificationType));
    }

    private static void assertNotificationsQueueHasMessageWithDestinationNotificationTypeAndCode(
            SqsQueueExtension notificationsQueue,
            String expectedDestination,
            NotificationType expectedNotificationType,
            String expectedCode) {
        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);
        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(expectedDestination));
        assertThat(requests.get(0).getNotificationType(), equalTo(expectedNotificationType));
        assertThat(requests.get(0).getCode(), equalTo(expectedCode));
    }

    private static void aUserHasEnteredAnOTPIncorrectlyTheMaximumAllowedTimes(
            String authenticatedSessionId) {
        for (int i = 0; i < ConfigurationService.getInstance().getCodeMaxRetries(); i++) {
            authSessionStore.incrementSessionCodeRequestCount(
                    authenticatedSessionId, MFA_SMS, JourneyType.REAUTHENTICATION);
        }
    }
}
