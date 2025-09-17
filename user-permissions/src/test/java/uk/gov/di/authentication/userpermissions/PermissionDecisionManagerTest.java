package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
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
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);

    private final PermissionDecisionManager permissionDecisionManager =
            new PermissionDecisionManager(
                    configurationService, codeStorageService, authenticationAttemptsService);

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
            assertEquals(false, lockedOut.isFirstTimeLimit());
        }

        @Test
        void shouldReturnLockedOutWithFirstTimeFlagWhenReachingLimitForFirstTime() {
            var userContext = createUserContext(5); // maxRetries - 1

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
            assertEquals(5, lockedOut.attemptCount());
            assertEquals(true, lockedOut.isFirstTimeLimit());
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
            assertEquals(ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST, lockedOut.forbiddenReason());
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

    @Nested
    class CanReceivePassword {

        @Test
        void shouldReturnPermittedWhenNotBlocked() {
            var userContext = createUserContext(0);
            when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(2);
            when(codeStorageService.isBlockedForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(false);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(2, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenBlocked() {
            var userContext = createUserContext(0);
            when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);
            when(codeStorageService.isBlockedForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(true);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess());
            var lockedOut =
                    assertInstanceOf(Decision.TemporarilyLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(5, lockedOut.attemptCount());
        }

        @Test
        void shouldReturnErrorWhenUserContextIsNull() {
            var result =
                    permissionDecisionManager.canReceivePassword(JourneyType.PASSWORD_RESET, null);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorWhenEmailAddressIsNull() {
            var userContext =
                    new UserPermissionContext("subject", "pairwise", null, new AuthSessionItem());

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorWhenJourneyTypeIsNull() {
            var userContext = createUserContext(0);

            var result = permissionDecisionManager.canReceivePassword(null, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnStorageErrorWhenExceptionThrown() {
            var userContext = createUserContext(0);
            doThrow(new RuntimeException("Storage error"))
                    .when(codeStorageService)
                    .getIncorrectPasswordCount(EMAIL);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.STORAGE_SERVICE_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnPermittedForReauthenticationJourney() {
            var userContext = createUserContext(3);
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            userContext.internalSubjectId(),
                            userContext.rpPairwiseId(),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(CountType.ENTER_PASSWORD, 2));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(2, decision.attemptCount());
        }

        @ParameterizedTest
        @MethodSource("countTypeToForbiddenReasonProvider")
        void shouldReturnTemporarilyLockedOutForReauthenticationWhenCountExceeded(
                CountType countType, ForbiddenReason expectedReason) {
            var userContext = createUserContext(3);
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            userContext.internalSubjectId(),
                            userContext.rpPairwiseId(),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(countType, 6));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut =
                    assertInstanceOf(Decision.TemporarilyLockedOut.class, result.getSuccess());
            assertEquals(expectedReason, lockedOut.forbiddenReason());
            assertEquals(6, lockedOut.attemptCount());
        }

        static Stream<Arguments> countTypeToForbiddenReasonProvider() {
            return Stream.of(
                    Arguments.of(
                            CountType.ENTER_PASSWORD,
                            ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT),
                    Arguments.of(
                            CountType.ENTER_EMAIL,
                            ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT),
                    Arguments.of(
                            CountType.ENTER_MFA_CODE,
                            ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT));
        }

        @Test
        void shouldReturnErrorForReauthenticationJourneyWhenInternalSubjectIdIsNull() {
            var userContext =
                    new UserPermissionContext(null, "pairwise", EMAIL, new AuthSessionItem());

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorForReauthenticationJourneyWhenRpPairwiseIdIsNull() {
            var userContext =
                    new UserPermissionContext("subject", null, EMAIL, new AuthSessionItem());

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }
    }

    @Nested
    class CanVerifyAuthAppOtp {

        @Test
        void shouldReturnPermittedWhenNotBlocked() {
            var userContext = createUserContext(0);
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(0L);

            var result =
                    permissionDecisionManager.canVerifyAuthAppOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenBlocked() {
            var userContext = createUserContext(0);
            long blockTtl = 1234567890L;
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(blockTtl);

            var result =
                    permissionDecisionManager.canVerifyAuthAppOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var lockedOut =
                    assertInstanceOf(Decision.TemporarilyLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(0, lockedOut.attemptCount());
        }

        @Test
        void shouldReturnStorageErrorWhenExceptionThrown() {
            var userContext = createUserContext(0);
            doThrow(new RuntimeException("Storage error"))
                    .when(codeStorageService)
                    .getMfaCodeBlockTimeToLive(EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN);

            var result =
                    permissionDecisionManager.canVerifyAuthAppOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.STORAGE_SERVICE_ERROR, result.getFailure());
        }
    }

    @Nested
    class SimplePermissionMethods {

        @Test
        void canReceiveEmailAddressShouldAlwaysReturnPermitted() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void canSendSmsOtpNotificationShouldAlwaysReturnPermitted() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void canVerifySmsOtpShouldAlwaysReturnPermitted() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canVerifySmsOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void canStartJourneyShouldAlwaysReturnPermitted() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canStartJourney(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void canVerifyOtpShouldDelegateToCanVerifyAuthAppOtp() {
            var userContext = createUserContext(0);
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(0L);

            var result = permissionDecisionManager.canVerifyOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
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
