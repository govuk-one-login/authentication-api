package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.CommonPasswordsExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.*;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PASSWORD = "Pa55word";
    private static final String INTERNAl_SECTOR_URI = "https://test.account.gov.uk";
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String RESET_PASSWORD_REQUEST =
            format(
                    """
                            {
                            "password": %s,
                            "isForcedPasswordReset": false
                            }
                            """,
                    PASSWORD);
    private static final String FORCED_RESET_PASSWORD_REQUEST =
            format(
                    """
                            {
                            "password": %s,
                            "isForcedPasswordReset": true
                            }
                            """,
                    PASSWORD);
    private static final String RESET_PASSWORD_REQUEST_WITH_ALLOW_MFA_RESET =
            format(
                    """
                            {
                            "password": %s,
                            "allowMfaResetAfterPasswordReset": true
                            }
                            """,
                    PASSWORD);

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordHandler(
                        new ResetPasswordTestConfigurationService(), redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldUpdatePasswordAndReturn204() throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(RESET_PASSWORD_REQUEST),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_PASSWORD_RESET_SUCCESSFUL));
    }

    @Test
    void shouldUpdatePasswordSendSMSAndWriteToAccountModifiersTableWhenUserHasVerifiedPhoneNumber()
            throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        var phoneNumber = "+441234567890";
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL_ADDRESS);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, phoneNumber);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(RESET_PASSWORD_REQUEST),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(2));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));
        assertThat(requests.get(1).getDestination(), equalTo(phoneNumber));
        assertThat(requests.get(1).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION_SMS));

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, AUTH_PASSWORD_RESET_SUCCESSFUL));
    }

    @Test
    void
            shouldUpdatePasswordSendSMSAndNotWriteToAccountModifiersTableWhenUserHasVerifiedPhoneNumberButRequestAllowsMfaReset()
                    throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        var phoneNumber = "+441234567890";
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL_ADDRESS);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, phoneNumber);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(RESET_PASSWORD_REQUEST_WITH_ALLOW_MFA_RESET),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(2));

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_PASSWORD_RESET_SUCCESSFUL));
    }

    @Test
    void shouldReturn400ForRequestWithCommonPassword() throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var body =
                format(
                        """
                            {
                            "password": "%s",
                            "isForcedPasswordReset": false
                            }
                            """,
                        CommonPasswordsExtension.TEST_COMMON_PASSWORD);

        var response =
                makeRequest(Optional.of(body), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertTrue(response.getBody().contains(ErrorResponse.ERROR_1040.getMessage()));
    }

    @Test
    void shouldSendForcedResetJourneyAuditEventWhenForcedPasswordResetIsTrue()
            throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(FORCED_RESET_PASSWORD_REQUEST),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTH_PASSWORD_RESET_INTERVENTION_COMPLETE, AUTH_PASSWORD_RESET_SUCCESSFUL));
    }

    private static Stream<Boolean> phoneNumberVerified() {
        return Stream.of(true, false);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVerified")
    void shouldUpdatePasswordAndWriteToAccountModifiersTableWithIfUserHasVerifiedPhoneNumber(
            boolean phoneNumberVerified) throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        var phoneNumber = "+441234567890";
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        userStore.setPhoneNumberAndVerificationStatus(
                EMAIL_ADDRESS, phoneNumber, phoneNumberVerified, phoneNumberVerified);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);
        byte[] salt = userStore.addSalt(EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(RESET_PASSWORD_REQUEST),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(phoneNumberVerified ? 2 : 1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        assertThat(
                accountModifiersStore.isBlockPresent(internalCommonSubjectId),
                equalTo(phoneNumberVerified));

        List<AuditableEvent> expectedAuditableEvents =
                phoneNumberVerified
                        ? List.of(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, AUTH_PASSWORD_RESET_SUCCESSFUL)
                        : List.of(AUTH_PASSWORD_RESET_SUCCESSFUL);
        assertTxmaAuditEventsReceived(txmaAuditQueue, expectedAuditableEvents);

        if (phoneNumberVerified) {
            assertThat(requests.get(1).getDestination(), equalTo(phoneNumber));
            assertThat(
                    requests.get(1).getNotificationType(),
                    equalTo(PASSWORD_RESET_CONFIRMATION_SMS));
        }
    }

    private static Stream<Boolean> authAppVerified() {
        return Stream.of(true, false);
    }

    @ParameterizedTest
    @MethodSource("authAppVerified")
    void shouldUpdatePasswordAndWriteToAccountRecoveryTableWithIfUserHasVerifiedAuthApp(
            boolean authAppVerified) throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionStore.addSession(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password-1", SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL_ADDRESS);
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, authAppVerified, true, "credential");
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(RESET_PASSWORD_REQUEST),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        assertThat(
                accountModifiersStore.isBlockPresent(internalCommonSubjectId),
                equalTo(authAppVerified));

        List<AuditableEvent> expectedAuditableEvents =
                authAppVerified
                        ? List.of(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, AUTH_PASSWORD_RESET_SUCCESSFUL)
                        : List.of(AUTH_PASSWORD_RESET_SUCCESSFUL);
        assertTxmaAuditEventsReceived(txmaAuditQueue, expectedAuditableEvents);
    }

    private static class ResetPasswordTestConfigurationService
            extends IntegrationTestConfigurationService {

        public ResetPasswordTestConfigurationService() {
            super(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }

        @Override
        public String getInternalSectorUri() {
            return INTERNAl_SECTOR_URI;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
