package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

class PermissionDecisionManagerTest {

    private static final String EMAIL = "test@example.com";
    private static final long LOCKOUT_DURATION = 799;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);

    private final PermissionDecisionManager permissionDecisionManager =
            new PermissionDecisionManager(codeStorageService, configurationService);

    @BeforeEach
    void setup() {
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
    }

    @Nested
    class CanSendEmailOtpNotification {

        @Test
        void shouldReturnPermittedForNonPasswordResetJourney() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            Decision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedWhenWithinLimits() {
            var userContext = createUserContext(3);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            Decision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(3, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenExceedsRequestCount() {
            var userContext = createUserContext(6);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var lockedOut =
                    assertInstanceOf(
                            Decision.TemporarilyLockedOut.class,
                            result.getSuccess(),
                            "Expected TemporarilyLockedOut decision");
            assertEquals(
                    ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(6, lockedOut.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenBlockedForRequests() {
            var userContext = createUserContext(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(EMAIL, codeRequestBlockedKeyPrefix))
                    .thenReturn(true);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var lockedOut =
                    assertInstanceOf(
                            Decision.TemporarilyLockedOut.class,
                            result.getSuccess(),
                            "Expected TemporarilyLockedOut decision");
            assertEquals(
                    ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                    lockedOut.forbiddenReason());
        }
    }

    @Nested
    class CanVerifyEmailOtp {

        @Test
        void shouldReturnPermittedForNonPasswordResetJourney() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canVerifyEmailOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            Decision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedWhenNotBlocked() {
            var userContext = createUserContext(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(EMAIL, codeAttemptsBlockedKeyPrefix))
                    .thenReturn(false);

            var result =
                    permissionDecisionManager.canVerifyEmailOtp(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            Decision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenBlockedForAttempts() {
            var userContext = createUserContext(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(EMAIL, codeAttemptsBlockedKeyPrefix))
                    .thenReturn(true);

            var result =
                    permissionDecisionManager.canVerifyEmailOtp(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var lockedOut =
                    assertInstanceOf(
                            Decision.TemporarilyLockedOut.class,
                            result.getSuccess(),
                            "Expected TemporarilyLockedOut decision");
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
        }
    }

    private UserPermissionContext createUserContext(int passwordResetCount) {
        var authSession = new AuthSessionItem().withEmailAddress(EMAIL);
        for (int i = 0; i < passwordResetCount; i++) {
            authSession = authSession.incrementPasswordResetCount();
        }

        return new UserPermissionContext(
                "internal-subject-id", "rp-pairwise-id", EMAIL, authSession);
    }
}
