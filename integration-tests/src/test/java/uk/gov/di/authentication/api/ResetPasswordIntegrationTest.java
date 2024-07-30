package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordCompletionRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.CommonPasswordsExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.*;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION_SMS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final Subject SUBJECT = new Subject();

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
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        redis.addEmailToSession(sessionId, EMAIL);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordCompletionRequest(VALID_PASSWORD, false)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(PASSWORD_RESET_SUCCESSFUL));
    }

    @Test
    void shouldUpdatePasswordSendSMSAndWriteToAccountModifiersTableWhenUserHasVerifiedPhoneNumber()
            throws Json.JsonException {
        var sessionId = redis.createSession();
        var phoneNumber = UK_LANDLINE_NUMBER;
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL);
        userStore.addVerifiedPhoneNumber(EMAIL, phoneNumber);
        redis.addEmailToSession(sessionId, EMAIL);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordCompletionRequest(VALID_PASSWORD, false)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(2));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));
        assertThat(requests.get(1).getDestination(), equalTo(phoneNumber));
        assertThat(requests.get(1).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION_SMS));

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(ACCOUNT_RECOVERY_BLOCK_ADDED, PASSWORD_RESET_SUCCESSFUL));
    }

    @Test
    void shouldReturn400ForRequestWithCommonPassword() throws Json.JsonException {
        var sessionId = redis.createSession();
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        redis.addEmailToSession(sessionId, EMAIL);

        var response =
                makeRequest(
                        Optional.of(
                                new ResetPasswordCompletionRequest(
                                        CommonPasswordsExtension.TEST_COMMON_PASSWORD, false)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertTrue(response.getBody().contains(ErrorResponse.ERROR_1040.getMessage()));
    }

    @Test
    void shouldSendForcedResetJourneyAuditEventWhenForcedPasswordResetIsTrue()
            throws Json.JsonException {
        var sessionId = redis.createSession();
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        redis.addEmailToSession(sessionId, EMAIL);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordCompletionRequest(VALID_PASSWORD, true)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(PASSWORD_RESET_INTERVENTION_COMPLETE, PASSWORD_RESET_SUCCESSFUL));
    }

    private static Stream<Boolean> phoneNumberVerified() {
        return Stream.of(true, false);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVerified")
    void shouldUpdatePasswordAndWriteToAccountModifiersTableWithIfUserHasVerifiedPhoneNumber(
            boolean phoneNumberVerified) throws Json.JsonException {
        var sessionId = redis.createSession();
        var phoneNumber = UK_LANDLINE_NUMBER;
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        userStore.setPhoneNumberAndVerificationStatus(
                EMAIL, phoneNumber, phoneNumberVerified, phoneNumberVerified);
        redis.addEmailToSession(sessionId, EMAIL);
        byte[] salt = userStore.addSalt(EMAIL);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordCompletionRequest(VALID_PASSWORD, false)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(phoneNumberVerified ? 2 : 1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
        assertThat(
                accountModifiersStore.isBlockPresent(internalCommonSubjectId),
                equalTo(phoneNumberVerified));

        List<AuditableEvent> expectedAuditableEvents =
                phoneNumberVerified
                        ? List.of(ACCOUNT_RECOVERY_BLOCK_ADDED, PASSWORD_RESET_SUCCESSFUL)
                        : List.of(PASSWORD_RESET_SUCCESSFUL);
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
        userStore.signUp(EMAIL, PASSWORD_OLD, SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL);
        userStore.addMfaMethod(EMAIL, MFAMethodType.AUTH_APP, authAppVerified, true, "credential");
        redis.addEmailToSession(sessionId, EMAIL);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordCompletionRequest(VALID_PASSWORD, false)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
        assertThat(
                accountModifiersStore.isBlockPresent(internalCommonSubjectId),
                equalTo(authAppVerified));

        List<AuditableEvent> expectedAuditableEvents =
                authAppVerified
                        ? List.of(ACCOUNT_RECOVERY_BLOCK_ADDED, PASSWORD_RESET_SUCCESSFUL)
                        : List.of(PASSWORD_RESET_SUCCESSFUL);
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
            return INTERNAL_SECTOR_URI;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
