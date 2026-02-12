package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

class PermissionDecisionManagerTest {

    private static final String EMAIL = "test@example.com";
    private static final String PHONE_NUMBER = "+447123456789";
    private static final long LOCKOUT_DURATION = 799;
    private static final int INTERNATIONAL_SMS_SEND_LIMIT = 10;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final InternationalSmsSendLimitService internationalSmsSendLimitService =
            mock(InternationalSmsSendLimitService.class);

    private final PermissionDecisionManager permissionDecisionManager =
            new PermissionDecisionManager(
                    configurationService,
                    codeStorageService,
                    authenticationAttemptsService,
                    internationalSmsSendLimitService);

    @BeforeEach
    void setup() {
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(internationalSmsSendLimitService.canSendSms(anyString())).thenReturn(true);
    }

    // Helper sealed interface to capture decision results in tests
    sealed interface TestDecision {
        record Permitted(int attemptCount) implements TestDecision {}

        record TemporarilyLockedOut(ForbiddenReason reason, int attemptCount, boolean isFirstTime)
                implements TestDecision {}

        record IndefinitelyLockedOut(ForbiddenReason reason, int attemptCount)
                implements TestDecision {}

        record ReauthLockedOut(
                ForbiddenReason reason,
                int attemptCount,
                Map<CountType, Integer> detailedCounts,
                List<CountType> blockedCountTypes)
                implements TestDecision {}
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class CanSendEmailOtpNotification {

        @Test
        void shouldReturnPermittedForNonPasswordResetJourney() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.SIGN_IN,
                            userContext,
                            permitted -> new TestDecision.Permitted(permitted.attemptCount()),
                            lockedOut ->
                                    new TestDecision.TemporarilyLockedOut(
                                            lockedOut.forbiddenReason(),
                                            lockedOut.attemptCount(),
                                            lockedOut.isFirstTimeLimit()));

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            TestDecision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedWhenWithinLimits() {
            var userContext = createUserContext(3);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.PASSWORD_RESET,
                            userContext,
                            permitted -> new TestDecision.Permitted(permitted.attemptCount()),
                            lockedOut ->
                                    new TestDecision.TemporarilyLockedOut(
                                            lockedOut.forbiddenReason(),
                                            lockedOut.attemptCount(),
                                            lockedOut.isFirstTimeLimit()));

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var decision =
                    assertInstanceOf(
                            TestDecision.Permitted.class,
                            result.getSuccess(),
                            "Expected Permitted decision");
            assertEquals(3, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenExceedsRequestCount() {
            var userContext = createUserContext(6);

            var result =
                    permissionDecisionManager.canSendEmailOtpNotification(
                            JourneyType.PASSWORD_RESET,
                            userContext,
                            permitted -> new TestDecision.Permitted(permitted.attemptCount()),
                            lockedOut ->
                                    new TestDecision.TemporarilyLockedOut(
                                            lockedOut.forbiddenReason(),
                                            lockedOut.attemptCount(),
                                            lockedOut.isFirstTimeLimit()));

            assertTrue(result.isSuccess(), "Expected result to be successful");
            var lockedOut =
                    assertInstanceOf(
                            TestDecision.TemporarilyLockedOut.class,
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

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
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

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
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
        void shouldReturnLockedOutWhenBlockedForPassword() {
            var userContext = createUserContext(0);
            when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);
            when(codeStorageService.isBlockedForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(true);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);

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
                    new PermissionContext("subject", "pairwise", null, new AuthSessionItem(), null);

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
            var identifiers = new ArrayList<String>();
            identifiers.add(userContext.internalSubjectId());
            identifiers.add(userContext.rpPairwiseId());
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            identifiers, JourneyType.REAUTHENTICATION))
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
        void shouldReturnReauthLockedOutForReauthenticationWhenCountExceeded(
                CountType countType, ForbiddenReason expectedReason) {
            var userContext = createUserContext(3);
            var identifiers = new ArrayList<String>();
            identifiers.add(userContext.internalSubjectId());
            identifiers.add(userContext.rpPairwiseId());
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            identifiers, JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(countType, 6));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
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
                    PermissionContext.builder()
                            .withRpPairwiseId("pairwise")
                            .withEmailAddress(EMAIL)
                            .withAuthSessionItem(new AuthSessionItem())
                            .build();

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorForReauthenticationJourneyWhenRpPairwiseIdIsNull() {
            var userContext =
                    new PermissionContext("subject", null, EMAIL, new AuthSessionItem(), null);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldUseMaxRetriesWhenBlockedForPasswordRegardlessOfCurrentCount() {
            var userContext = createUserContext(0);
            when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(3);
            when(codeStorageService.isBlockedForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(true);
            when(configurationService.getMaxPasswordRetries()).thenReturn(7);

            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.PASSWORD_RESET, userContext);

            assertTrue(result.isSuccess());
            var lockedOut =
                    assertInstanceOf(Decision.TemporarilyLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(7, lockedOut.attemptCount());
        }
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class CanSendSmsOtpNotification {

        @Test
        void shouldReturnErrorWhenPhoneNumberIsNull() {
            var userContext = createUserContext(0, EMAIL, null);

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorWhenEmailIsNull() {
            var userContext = createUserContext(0, null, Optional.of(PHONE_NUMBER));

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnIndefinitelyLockedOutWhenInternationalSmsLimitExceeded() {
            var userContext = createUserContext(0);

            when(internationalSmsSendLimitService.canSendSms(PHONE_NUMBER)).thenReturn(false);
            when(configurationService.getInternationalSmsNumberSendLimit())
                    .thenReturn(INTERNATIONAL_SMS_SEND_LIMIT);

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            verify(internationalSmsSendLimitService).canSendSms(PHONE_NUMBER);
            assertTrue(result.isSuccess());
            var decision =
                    assertInstanceOf(Decision.IndefinitelyLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                    decision.forbiddenReason());
            assertEquals(INTERNATIONAL_SMS_SEND_LIMIT, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedWhenInternationalSmsLimitNotExceeded() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            verify(internationalSmsSendLimitService).canSendSms(PHONE_NUMBER);
            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnStorageErrorWhenInternationalSmsServiceThrowsException() {
            var userContext = createUserContext(0);

            when(internationalSmsSendLimitService.canSendSms(anyString()))
                    .thenThrow(new RuntimeException("Service error"));

            var result =
                    permissionDecisionManager.canSendSmsOtpNotification(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.STORAGE_SERVICE_ERROR, result.getFailure());
        }
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class CanVerifyMfaOtp {

        @Test
        void shouldReturnPermittedWhenNotBlocked() {
            var userContext = createUserContext(0);
            when(codeStorageService.getTTL(eq(EMAIL), anyString())).thenReturn(0L);

            var result =
                    permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutWhenBlocked() {
            var userContext = createUserContext(0);
            long blockTtl = 1234567890L;
            when(codeStorageService.getTTL(eq(EMAIL), anyString())).thenReturn(blockTtl);

            var result =
                    permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var lockedOut =
                    assertInstanceOf(Decision.TemporarilyLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(6, lockedOut.attemptCount());
        }

        @Test
        void shouldReturnStorageErrorWhenExceptionThrown() {
            var userContext = createUserContext(0);
            doThrow(new RuntimeException("Storage error"))
                    .when(codeStorageService)
                    .getTTL(eq(EMAIL), anyString());

            var result =
                    permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.STORAGE_SERVICE_ERROR, result.getFailure());
        }
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class CanStartJourney {

        @Test
        void shouldReturnPermittedForNonReauthJourney() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canStartJourney(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedForReauthWhenNotBlocked() {
            var userContext = createUserContext(0);
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(CountType.ENTER_PASSWORD, 2));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnReauthLockedOutWhenPasswordCountExceeded() {
            var userContext = createUserContext(0);
            var counts = Map.of(CountType.ENTER_PASSWORD, 6);
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(counts);
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(counts, lockedOut.detailedCounts());
            assertEquals(1, lockedOut.blockedCountTypes().size());
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_PASSWORD));
        }

        @Test
        void shouldReturnReauthLockedOutWhenEmailCountExceeded() {
            var userContext = createUserContext(0);
            var counts = Map.of(CountType.ENTER_EMAIL, 6);
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(counts);
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(counts, lockedOut.detailedCounts());
            assertEquals(1, lockedOut.blockedCountTypes().size());
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_EMAIL));
        }

        @Test
        void shouldReturnReauthLockedOutWhenMfaCountExceeded() {
            var userContext = createUserContext(0);
            var counts = Map.of(CountType.ENTER_MFA_CODE, 6);
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(counts);
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(counts, lockedOut.detailedCounts());
            assertEquals(1, lockedOut.blockedCountTypes().size());
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_MFA_CODE));
        }

        @Test
        void shouldUseGetCountsByJourneyWhenInternalSubjectIdIsNull() {
            var userContext =
                    PermissionContext.builder()
                            .withRpPairwiseId("rp-pairwise-id")
                            .withEmailAddress(EMAIL)
                            .withAuthSessionItem(new AuthSessionItem())
                            .build();
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Collections.singletonList(userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(CountType.ENTER_PASSWORD, 2));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnReauthLockedOutWithMultipleBlockedCountTypes() {
            var userContext = createUserContext(0);
            var counts =
                    Map.of(
                            CountType.ENTER_PASSWORD, 6,
                            CountType.ENTER_EMAIL, 6,
                            CountType.ENTER_MFA_CODE, 3);

            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(counts);
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(counts, lockedOut.detailedCounts());
            assertEquals(2, lockedOut.blockedCountTypes().size());
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_PASSWORD));
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_EMAIL));
        }

        @Test
        void shouldReturnReauthLockedOutWhenEmailCodeCountExceeded() {
            var userContext = createUserContext(0);
            var counts = Map.of(CountType.ENTER_EMAIL_CODE, 6);
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            Arrays.asList(
                                    userContext.internalSubjectId(), userContext.rpPairwiseId()),
                            JourneyType.REAUTHENTICATION))
                    .thenReturn(counts);
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
            when(configurationService.getMaxPasswordRetries()).thenReturn(5);
            when(configurationService.getCodeMaxRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canStartJourney(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(counts, lockedOut.detailedCounts());
            assertEquals(1, lockedOut.blockedCountTypes().size());
            assertTrue(lockedOut.blockedCountTypes().contains(CountType.ENTER_EMAIL_CODE));
        }
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class CanReceiveEmailAddress {

        @Test
        void shouldReturnPermittedForNonReauthenticationJourney() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void shouldReturnPermittedForReauthenticationWhenNotLocked() {
            var userContext = createUserContext(0);
            var identifiers = new ArrayList<String>();
            identifiers.add(userContext.internalSubjectId());
            identifiers.add(userContext.rpPairwiseId());
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            identifiers, JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(CountType.ENTER_EMAIL, 2));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(2, decision.attemptCount());
        }

        @Test
        void shouldReturnLockedOutForReauthenticationWhenLocked() {
            var userContext = createUserContext(0);
            var identifiers = new ArrayList<String>();
            identifiers.add(userContext.internalSubjectId());
            identifiers.add(userContext.rpPairwiseId());
            when(authenticationAttemptsService.getCountsByJourneyForIdentifiers(
                            identifiers, JourneyType.REAUTHENTICATION))
                    .thenReturn(Map.of(CountType.ENTER_EMAIL, 6));
            when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isSuccess());
            var lockedOut = assertInstanceOf(Decision.ReauthLockedOut.class, result.getSuccess());
            assertEquals(
                    ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT,
                    lockedOut.forbiddenReason());
            assertEquals(6, lockedOut.attemptCount());
        }

        @Test
        void shouldReturnErrorForReauthenticationWithNullInternalSubjectIds() {
            var userContext =
                    new PermissionContext(
                            (List<String>) null,
                            "rp-pairwise-id",
                            EMAIL,
                            new AuthSessionItem(),
                            null);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }

        @Test
        void shouldReturnErrorForReauthenticationWithNullRpPairwiseId() {
            var userContext =
                    new PermissionContext(
                            List.of("internal-subject-id"),
                            null,
                            EMAIL,
                            new AuthSessionItem(),
                            null);

            var result =
                    permissionDecisionManager.canReceiveEmailAddress(
                            JourneyType.REAUTHENTICATION, userContext);

            assertTrue(result.isFailure());
            assertEquals(DecisionError.INVALID_USER_CONTEXT, result.getFailure());
        }
    }

    @Disabled("Needs lambda conversion - see TEST_UPDATE_GUIDE.md")
    @Nested
    class SimplePermissionMethods {

        @Test
        void canVerifySmsOtpShouldAlwaysReturnPermitted() {
            var userContext = createUserContext(0);

            var result =
                    permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }

        @Test
        void canVerifyOtpShouldDelegateToCanVerifyMfaOtp() {
            var userContext = createUserContext(0);
            when(codeStorageService.getTTL(eq(EMAIL), anyString())).thenReturn(0L);

            var result =
                    permissionDecisionManager.canVerifyMfaOtp(JourneyType.SIGN_IN, userContext);

            assertTrue(result.isSuccess());
            var decision = assertInstanceOf(Decision.Permitted.class, result.getSuccess());
            assertEquals(0, decision.attemptCount());
        }
    }

    private PermissionContext createUserContext(int passwordResetCount) {
        return createUserContext(passwordResetCount, EMAIL, Optional.of(PHONE_NUMBER));
    }

    private PermissionContext createUserContext(
            int passwordResetCount, String email, Optional<String> phoneNumber) {
        var authSession = new AuthSessionItem().withEmailAddress(email);
        for (int i = 0; i < passwordResetCount; i++) {
            authSession = authSession.incrementPasswordResetCount();
        }

        return new PermissionContext(
                "internal-subject-id", "rp-pairwise-id", email, authSession, phoneNumber);
    }
}
