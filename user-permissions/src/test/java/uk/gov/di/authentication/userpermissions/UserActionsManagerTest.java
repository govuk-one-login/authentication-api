package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CodeRequestType.SupportedCodeType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.InMemoryLockoutStateHolder;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

class UserActionsManagerTest {

    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private UserActionsManager userActionsManager;

    private static final String EMAIL = "test@example.com";
    private static final String SESSION_ID = "session-123";
    private final AuthSessionItem authSession =
            new AuthSessionItem().withSessionId(SESSION_ID).withEmailAddress(EMAIL);
    private final PermissionContext permissionContext =
            PermissionContext.builder()
                    .withEmailAddress(EMAIL)
                    .withAuthSessionItem(authSession)
                    .build();

    @BeforeEach
    void setUp() {
        userActionsManager =
                new UserActionsManager(
                        configurationService,
                        codeStorageService,
                        authSessionService,
                        authenticationAttemptsService);
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(configurationService.getIncreasedCodeMaxRetries()).thenReturn(999999);
        when(configurationService.getLockoutDuration()).thenReturn(900L);
    }

    @Nested
    class CreatedPasswordOperations {
        @Test
        void passwordCreatedShouldSetHasVerifiedPasswordToTrue() {
            // Arrange
            ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);

            // Act
            var result = userActionsManager.createdPassword(null, permissionContext);

            // Assert
            verify(authSessionService).updateSession(captor.capture());
            AuthSessionItem capturedSession = captor.getValue();
            assertTrue(capturedSession.getHasVerifiedPassword());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class CorrectPasswordReceivedOperations {
        @Test
        void correctPasswordReceivedShouldSetHasVerifiedPasswordToTrue() {
            // Arrange
            ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);

            // Act
            var result = userActionsManager.correctPasswordReceived(null, permissionContext);

            // Assert
            verify(authSessionService).updateSession(captor.capture());
            AuthSessionItem capturedSession = captor.getValue();
            assertTrue(capturedSession.getHasVerifiedPassword());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class PasswordResetOperations {

        @Test
        void passwordResetShouldDeleteIncorrectPasswordCountAndBlock() {
            var result =
                    userActionsManager.passwordReset(JourneyType.PASSWORD_RESET, permissionContext);

            verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
            verify(codeStorageService)
                    .deleteBlockForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET);
            assertTrue(result.isSuccess());
        }

        @Test
        void passwordResetShouldHandleDifferentJourneyTypes() {
            var result = userActionsManager.passwordReset(JourneyType.SIGN_IN, permissionContext);

            verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
            verify(codeStorageService)
                    .deleteBlockForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.SIGN_IN);
            assertTrue(result.isSuccess());
        }

        @Test
        void passwordResetShouldSetHasVerifiedPasswordToTrue() {
            // Arrange
            ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);

            // Act
            var result = userActionsManager.passwordReset(null, permissionContext);

            // Assert
            verify(authSessionService).updateSession(captor.capture());
            AuthSessionItem capturedSession = captor.getValue();
            assertTrue(capturedSession.getHasVerifiedPassword());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class EmailOtpNotificationOperations {

        @Nested
        class PasswordResetJourney {

            @Test
            void shouldIncrementPasswordResetCount() {
                var result =
                        userActionsManager.sentEmailOtpNotification(
                                JourneyType.PASSWORD_RESET, permissionContext);

                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService).updateSession(captor.capture());
                assertEquals(1, captor.getValue().getPasswordResetCount());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockAndResetCountWhenMaxRetriesReached() {
                var sessionWithMaxCount = authSession;
                for (int i = 0; i < 5; i++) {
                    sessionWithMaxCount = sessionWithMaxCount.incrementPasswordResetCount();
                }
                var contextWithMaxCount =
                        PermissionContext.builder()
                                .withEmailAddress(EMAIL)
                                .withAuthSessionItem(sessionWithMaxCount)
                                .build();

                var result =
                        userActionsManager.sentEmailOtpNotification(
                                JourneyType.PASSWORD_RESET, contextWithMaxCount);

                var expectedBlockedKey =
                        CODE_REQUEST_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
                verify(codeStorageService)
                        .saveBlockedForEmail(eq(EMAIL), eq(expectedBlockedKey), eq(900L));
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService, times(2)).updateSession(captor.capture());
                assertEquals(0, captor.getAllValues().get(1).getPasswordResetCount());
                assertTrue(result.isSuccess());
            }
        }

        @Nested
        class RegistrationAndAccountRecoveryJourneys {

            static Stream<Arguments> journeyTypeAndNotificationType() {
                return Stream.of(
                        Arguments.of(JourneyType.REGISTRATION, VERIFY_EMAIL),
                        Arguments.of(
                                JourneyType.ACCOUNT_RECOVERY,
                                VERIFY_CHANGE_HOW_GET_SECURITY_CODES));
            }

            @ParameterizedTest
            @MethodSource("journeyTypeAndNotificationType")
            void shouldIncrementCodeRequestCount(
                    JourneyType journeyType, NotificationType notificationType) {
                var result =
                        userActionsManager.sentEmailOtpNotification(journeyType, permissionContext);

                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService).updateSession(captor.capture());
                assertEquals(
                        1, captor.getValue().getCodeRequestCount(notificationType, journeyType));
                assertTrue(result.isSuccess());
            }

            @ParameterizedTest
            @MethodSource("journeyTypeAndNotificationType")
            void shouldBlockAndResetCountWhenMaxRetriesReached(
                    JourneyType journeyType, NotificationType notificationType) {
                var sessionWithMaxCount = authSession;
                for (int i = 0; i < 5; i++) {
                    sessionWithMaxCount =
                            sessionWithMaxCount.incrementCodeRequestCount(
                                    notificationType, journeyType);
                }
                var contextWithMaxCount =
                        PermissionContext.builder()
                                .withEmailAddress(EMAIL)
                                .withAuthSessionItem(sessionWithMaxCount)
                                .build();

                var result =
                        userActionsManager.sentEmailOtpNotification(
                                journeyType, contextWithMaxCount);

                var expectedBlockedKey =
                        CODE_REQUEST_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(notificationType, journeyType);
                verify(codeStorageService)
                        .saveBlockedForEmail(eq(EMAIL), eq(expectedBlockedKey), eq(900L));
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService, times(2)).updateSession(captor.capture());
                assertEquals(
                        0,
                        captor.getAllValues()
                                .get(1)
                                .getCodeRequestCount(notificationType, journeyType));
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldClearIncorrectEmailOtpBlockWhenNewCodeRequestedForRegistration() {
                userActionsManager.sentEmailOtpNotification(
                        JourneyType.REGISTRATION, permissionContext);

                verify(codeStorageService)
                        .deleteBlockForEmail(
                                EMAIL,
                                CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                        + CodeRequestType.EMAIL_REGISTRATION);
            }
        }

        @Nested
        class UnsupportedJourneys {

            @Test
            void shouldDoNothingForUnsupportedJourneyType() {
                var result =
                        userActionsManager.sentEmailOtpNotification(
                                JourneyType.SIGN_IN, permissionContext);

                verify(authSessionService, never()).updateSession(any());
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }
        }
    }

    @Nested
    class IncorrectPasswordReceived {

        @Test
        void shouldCreateOrIncrementCountForReauthenticationJourney() {
            var contextWithSubjectId =
                    new PermissionContext("subject-123", "pairwise-456", EMAIL, authSession, null);
            when(configurationService.getReauthEnterPasswordCountTTL()).thenReturn(120L);

            var result =
                    userActionsManager.incorrectPasswordReceived(
                            JourneyType.REAUTHENTICATION, contextWithSubjectId);

            verify(authenticationAttemptsService)
                    .createOrIncrementCount(
                            eq("subject-123"),
                            anyLong(),
                            eq(JourneyType.REAUTHENTICATION),
                            eq(CountType.ENTER_PASSWORD));
            assertTrue(result.isSuccess());
        }

        @Test
        void shouldIncreaseIncorrectPasswordCountForSignInJourney() {
            when(codeStorageService.increaseIncorrectPasswordCount(EMAIL)).thenReturn(3);
            when(configurationService.getMaxPasswordRetries()).thenReturn(6);

            var result =
                    userActionsManager.incorrectPasswordReceived(
                            JourneyType.SIGN_IN, permissionContext);

            verify(codeStorageService).increaseIncorrectPasswordCount(EMAIL);
            verify(codeStorageService, never())
                    .saveBlockedForEmail(anyString(), anyString(), anyLong());
            verify(codeStorageService, never()).deleteIncorrectPasswordCount(anyString());
            assertTrue(result.isSuccess());
        }

        @Test
        void shouldBlockUserWhenMaxPasswordRetriesReachedForSignInJourney() {
            when(codeStorageService.increaseIncorrectPasswordCount(EMAIL)).thenReturn(6);
            when(configurationService.getMaxPasswordRetries()).thenReturn(6);
            when(configurationService.getLockoutDuration()).thenReturn(900L);

            var result =
                    userActionsManager.incorrectPasswordReceived(
                            JourneyType.SIGN_IN, permissionContext);

            verify(codeStorageService).increaseIncorrectPasswordCount(EMAIL);
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET,
                            900L);
            verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class IncorrectEmailAddressReceived {

        @Test
        void shouldIncrementCountForReauthenticationJourney() {
            var context =
                    PermissionContext.builder()
                            .withInternalSubjectId("internal-subject-id")
                            .withRpPairwiseId("rp-pairwise-id")
                            .build();
            when(configurationService.getReauthEnterEmailCountTTL()).thenReturn(900L);

            var result =
                    userActionsManager.incorrectEmailAddressReceived(
                            JourneyType.REAUTHENTICATION, context);

            assertTrue(result.isSuccess());
            verify(authenticationAttemptsService)
                    .createOrIncrementCount(
                            eq("internal-subject-id"),
                            anyLong(),
                            eq(JourneyType.REAUTHENTICATION),
                            eq(CountType.ENTER_EMAIL));
        }

        @Test
        void shouldUseRpPairwiseIdWhenInternalSubjectIdIsNull() {
            var context =
                    PermissionContext.builder()
                            .withInternalSubjectId(null)
                            .withRpPairwiseId("rp-pairwise-id")
                            .build();
            when(configurationService.getReauthEnterEmailCountTTL()).thenReturn(900L);

            var result =
                    userActionsManager.incorrectEmailAddressReceived(
                            JourneyType.REAUTHENTICATION, context);

            assertTrue(result.isSuccess());
            verify(authenticationAttemptsService)
                    .createOrIncrementCount(
                            eq("rp-pairwise-id"),
                            anyLong(),
                            eq(JourneyType.REAUTHENTICATION),
                            eq(CountType.ENTER_EMAIL));
        }

        @Test
        void shouldReturnStorageErrorWhenExceptionThrown() {
            var context =
                    PermissionContext.builder()
                            .withInternalSubjectId("internal-subject-id")
                            .withRpPairwiseId("rp-pairwise-id")
                            .build();
            when(configurationService.getReauthEnterEmailCountTTL()).thenReturn(900L);
            doThrow(new RuntimeException("Storage error"))
                    .when(authenticationAttemptsService)
                    .createOrIncrementCount(anyString(), anyLong(), any(), any());

            var result =
                    userActionsManager.incorrectEmailAddressReceived(
                            JourneyType.REAUTHENTICATION, context);

            assertTrue(result.isFailure());
            assertEquals(TrackingError.STORAGE_SERVICE_ERROR, result.getFailure());
        }
    }

    @Nested
    class CorrectSmsOtpReceived {
        @Test
        void correctSmsOtpReceivedShouldSetHasVerifiedMfaToTrue() {
            // Arrange
            ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);

            // Act
            var result = userActionsManager.correctSmsOtpReceived(null, permissionContext);

            // Assert
            verify(authSessionService).updateSession(captor.capture());
            AuthSessionItem capturedSession = captor.getValue();
            assertTrue(capturedSession.getHasVerifiedMfa());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class SentSmsOtpNotificationOperations {

        @Nested
        class StandardJourneys {

            static Stream<JourneyType> journeyTypes() {
                return Stream.of(JourneyType.SIGN_IN, JourneyType.REGISTRATION);
            }

            @ParameterizedTest
            @MethodSource("journeyTypes")
            void shouldIncrementCodeRequestCount(JourneyType journeyType) {
                var result =
                        userActionsManager.sentSmsOtpNotification(journeyType, permissionContext);

                var codeRequestType =
                        CodeRequestType.getCodeRequestType(SupportedCodeType.MFA, journeyType);
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService).updateSession(captor.capture());
                assertEquals(1, captor.getValue().getCodeRequestCount(codeRequestType));
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }

            @ParameterizedTest
            @MethodSource("journeyTypes")
            void shouldBlockAndResetCountWhenMaxRetriesReached(JourneyType journeyType) {
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(SupportedCodeType.MFA, journeyType);
                var sessionWithMaxCount = authSession;
                for (int i = 0; i < 5; i++) {
                    sessionWithMaxCount =
                            sessionWithMaxCount.incrementCodeRequestCount(codeRequestType);
                }
                var contextWithMaxCount =
                        PermissionContext.builder()
                                .withEmailAddress(EMAIL)
                                .withAuthSessionItem(sessionWithMaxCount)
                                .build();

                var result =
                        userActionsManager.sentSmsOtpNotification(journeyType, contextWithMaxCount);

                var expectedBlockedKey = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 900L);
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService, times(2)).updateSession(captor.capture());
                assertEquals(0, captor.getAllValues().get(1).getCodeRequestCount(codeRequestType));
                assertTrue(result.isSuccess());
            }
        }

        @Nested
        class ReauthenticationJourney {
            @Test
            void shouldIncrementCodeRequestCount() {
                var result =
                        userActionsManager.sentSmsOtpNotification(
                                JourneyType.REAUTHENTICATION, permissionContext);

                var codeRequestType =
                        CodeRequestType.getCodeRequestType(
                                SupportedCodeType.MFA, JourneyType.REAUTHENTICATION);
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService).updateSession(captor.capture());
                assertEquals(1, captor.getValue().getCodeRequestCount(codeRequestType));
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockAndResetCountWhenReauthSignoutDisabled() {
                when(configurationService.supportReauthSignoutEnabled()).thenReturn(false);
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(
                                SupportedCodeType.MFA, JourneyType.REAUTHENTICATION);
                var sessionWithMaxCount = authSession;
                for (int i = 0; i < 5; i++) {
                    sessionWithMaxCount =
                            sessionWithMaxCount.incrementCodeRequestCount(codeRequestType);
                }
                var contextWithMaxCount =
                        PermissionContext.builder()
                                .withEmailAddress(EMAIL)
                                .withAuthSessionItem(sessionWithMaxCount)
                                .build();

                var result =
                        userActionsManager.sentSmsOtpNotification(
                                JourneyType.REAUTHENTICATION, contextWithMaxCount);

                var expectedBlockedKey = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 900L);
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService, times(2)).updateSession(captor.capture());
                assertEquals(0, captor.getAllValues().get(1).getCodeRequestCount(codeRequestType));
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldSetInMemoryLockoutStateHolderAndResetCountWhenReauthSignoutEnabled() {
                when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(
                                SupportedCodeType.MFA, JourneyType.REAUTHENTICATION);
                var sessionWithMaxCount = authSession;
                for (int i = 0; i < 5; i++) {
                    sessionWithMaxCount =
                            sessionWithMaxCount.incrementCodeRequestCount(codeRequestType);
                }
                var contextWithMaxCount =
                        PermissionContext.builder()
                                .withEmailAddress(EMAIL)
                                .withAuthSessionItem(sessionWithMaxCount)
                                .build();
                var lockoutStateHolder = new InMemoryLockoutStateHolder();

                var result =
                        userActionsManager.sentSmsOtpNotification(
                                JourneyType.REAUTHENTICATION,
                                contextWithMaxCount,
                                lockoutStateHolder);

                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(lockoutStateHolder.isReauthSmsOtpLimitExceeded());
                ArgumentCaptor<AuthSessionItem> captor =
                        ArgumentCaptor.forClass(AuthSessionItem.class);
                verify(authSessionService, times(2)).updateSession(captor.capture());
                assertEquals(0, captor.getAllValues().get(1).getCodeRequestCount(codeRequestType));
                assertTrue(result.isSuccess());
            }
        }
    }

    @Nested
    class CorrectAuthAppOtpReceived {
        @Test
        void correctAuthAppOtpReceivedShouldSetHasVerifiedMfaToTrue() {
            // Arrange
            ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);

            // Act
            var result = userActionsManager.correctAuthAppOtpReceived(null, permissionContext);

            // Assert
            verify(authSessionService).updateSession(captor.capture());
            AuthSessionItem capturedSession = captor.getValue();
            assertTrue(capturedSession.getHasVerifiedMfa());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class IncorrectSmsOtpReceived {

        @Nested
        class StandardJourneys {

            @Test
            void shouldIncrementCount() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

                var result =
                        userActionsManager.incorrectSmsOtpReceived(
                                JourneyType.SIGN_IN, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWhenMaxRetriesReached() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);

                var result =
                        userActionsManager.incorrectSmsOtpReceived(
                                JourneyType.SIGN_IN, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        SupportedCodeType.MFA, JourneyType.SIGN_IN);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 900L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @ParameterizedTest
            @MethodSource("reducedIncorrectSmsOtpReceivedLockoutJourneyTypes")
            void shouldUseReducedLockoutDurationForReducedLockoutJourneys(JourneyType journeyType) {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);
                when(configurationService.getReducedLockoutDuration()).thenReturn(300L);

                var result =
                        userActionsManager.incorrectSmsOtpReceived(journeyType, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        SupportedCodeType.MFA, journeyType);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 300L);
                assertTrue(result.isSuccess());
            }

            static Stream<JourneyType> reducedIncorrectSmsOtpReceivedLockoutJourneyTypes() {
                return Stream.of(JourneyType.REGISTRATION, JourneyType.ACCOUNT_RECOVERY);
            }
        }

        @Nested
        class ReauthenticationJourney {

            @Test
            void shouldIncrementCountViaAuthAttemptsService() {
                var context =
                        PermissionContext.builder().withInternalSubjectId("subject-123").build();
                when(configurationService.getReauthEnterSMSCodeCountTTL()).thenReturn(120L);

                var result =
                        userActionsManager.incorrectSmsOtpReceived(
                                JourneyType.REAUTHENTICATION, context);

                verify(authenticationAttemptsService)
                        .createOrIncrementCount(
                                eq("subject-123"),
                                anyLong(),
                                eq(JourneyType.REAUTHENTICATION),
                                eq(CountType.ENTER_MFA_CODE));
                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCount(anyString());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldReturnErrorWhenAuthAttemptsServiceThrows() {
                var context =
                        PermissionContext.builder().withInternalSubjectId("subject-123").build();
                when(configurationService.getReauthEnterSMSCodeCountTTL()).thenReturn(120L);
                doThrow(new RuntimeException("Storage error"))
                        .when(authenticationAttemptsService)
                        .createOrIncrementCount(anyString(), anyLong(), any(), any());

                var result =
                        userActionsManager.incorrectSmsOtpReceived(
                                JourneyType.REAUTHENTICATION, context);

                assertTrue(result.isFailure());
                assertEquals(TrackingError.STORAGE_SERVICE_ERROR, result.getFailure());
            }
        }
    }

    @Nested
    class IncorrectAuthAppOtpReceived {

        @Nested
        class StandardJourneys {

            @Test
            void shouldIncrementCount() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                JourneyType.SIGN_IN, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWhenMaxRetriesReached() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                JourneyType.SIGN_IN, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        MFAMethodType.AUTH_APP, JourneyType.SIGN_IN);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 900L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @ParameterizedTest
            @MethodSource("reducedIncorrectAuthAppOtpReceivedLockoutJourneyTypes")
            void shouldAllowSignificantlyHigherAttemptsForRegistrationAndAccountRecovery(
                    JourneyType journeyType) {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL))
                        .thenReturn(999998);

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                journeyType, permissionContext);

                verify(codeStorageService, never()).saveBlockedForEmail(any(), any(), anyLong());
                assertTrue(result.isSuccess());
            }

            @ParameterizedTest
            @MethodSource("reducedIncorrectAuthAppOtpReceivedLockoutJourneyTypes")
            void shouldUseReducedLockoutDurationForReducedLockoutJourneys(JourneyType journeyType) {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL))
                        .thenReturn(999999);
                when(configurationService.getReducedLockoutDuration()).thenReturn(300L);

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                journeyType, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        MFAMethodType.AUTH_APP, journeyType);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 300L);
                assertTrue(result.isSuccess());
            }

            static Stream<JourneyType> reducedIncorrectAuthAppOtpReceivedLockoutJourneyTypes() {
                return Stream.of(JourneyType.REGISTRATION, JourneyType.ACCOUNT_RECOVERY);
            }
        }

        @Nested
        class ReauthenticationJourney {

            @Test
            void shouldIncrementCountViaAuthAttemptsService() {
                var context =
                        PermissionContext.builder().withInternalSubjectId("subject-123").build();
                when(configurationService.getReauthEnterAuthAppCodeCountTTL()).thenReturn(120L);

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                JourneyType.REAUTHENTICATION, context);

                verify(authenticationAttemptsService)
                        .createOrIncrementCount(
                                eq("subject-123"),
                                anyLong(),
                                eq(JourneyType.REAUTHENTICATION),
                                eq(CountType.ENTER_MFA_CODE));
                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCount(anyString());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldReturnErrorWhenAuthAttemptsServiceThrows() {
                var context =
                        PermissionContext.builder().withInternalSubjectId("subject-123").build();
                when(configurationService.getReauthEnterAuthAppCodeCountTTL()).thenReturn(120L);
                doThrow(new RuntimeException("Storage error"))
                        .when(authenticationAttemptsService)
                        .createOrIncrementCount(anyString(), anyLong(), any(), any());

                var result =
                        userActionsManager.incorrectAuthAppOtpReceived(
                                JourneyType.REAUTHENTICATION, context);

                assertTrue(result.isFailure());
                assertEquals(TrackingError.STORAGE_SERVICE_ERROR, result.getFailure());
            }
        }
    }

    @Nested
    class IncorrectEmailOtpReceived {

        @Nested
        class PasswordResetAndAccountRecoveryJourneys {

            @ParameterizedTest
            @EnumSource(
                    value = JourneyType.class,
                    names = {"PASSWORD_RESET", "ACCOUNT_RECOVERY"})
            void shouldIncrementCount(JourneyType journeyType) {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                journeyType, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWithStandardLockoutForPasswordReset() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.PASSWORD_RESET, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        CodeRequestType.SupportedCodeType.EMAIL,
                                        JourneyType.PASSWORD_RESET);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 900L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWithReducedLockoutForAccountRecovery() {
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);
                when(configurationService.getReducedLockoutDuration()).thenReturn(300L);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.ACCOUNT_RECOVERY, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        CodeRequestType.SupportedCodeType.EMAIL,
                                        JourneyType.ACCOUNT_RECOVERY);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 300L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }
        }

        @Nested
        class RegistrationJourney {

            @Test
            void shouldIncrementCountUsingAccountCreationMethodWhenConfigEnabled() {
                when(configurationService.supportAccountCreationTTL()).thenReturn(true);
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCountAccountCreation(EMAIL))
                        .thenReturn(1);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.REGISTRATION, permissionContext);

                verify(codeStorageService)
                        .increaseIncorrectMfaCodeAttemptsCountAccountCreation(EMAIL);
                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCount(anyString());
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldIncrementCountUsingStandardMethodWhenConfigDisabled() {
                when(configurationService.supportAccountCreationTTL()).thenReturn(false);
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.REGISTRATION, permissionContext);

                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL);
                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCountAccountCreation(anyString());
                verify(codeStorageService, never())
                        .saveBlockedForEmail(anyString(), anyString(), anyLong());
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWithReducedLockoutWhenConfigEnabled() {
                when(configurationService.supportAccountCreationTTL()).thenReturn(true);
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCountAccountCreation(EMAIL))
                        .thenReturn(6);
                when(configurationService.getReducedLockoutDuration()).thenReturn(300L);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.REGISTRATION, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        CodeRequestType.SupportedCodeType.EMAIL,
                                        JourneyType.REGISTRATION);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 300L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }

            @Test
            void shouldBlockWithReducedLockoutWhenConfigDisabled() {
                when(configurationService.supportAccountCreationTTL()).thenReturn(false);
                when(codeStorageService.increaseIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);
                when(configurationService.getReducedLockoutDuration()).thenReturn(300L);

                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.REGISTRATION, permissionContext);

                var expectedBlockedKey =
                        CodeStorageService.CODE_BLOCKED_KEY_PREFIX
                                + CodeRequestType.getCodeRequestType(
                                        CodeRequestType.SupportedCodeType.EMAIL,
                                        JourneyType.REGISTRATION);
                verify(codeStorageService).saveBlockedForEmail(EMAIL, expectedBlockedKey, 300L);
                verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
                assertTrue(result.isSuccess());
            }
        }

        @Nested
        class ReauthenticationJourney {

            @Test
            void shouldDoNothingForReauthentication() {
                var result =
                        userActionsManager.incorrectEmailOtpReceived(
                                JourneyType.REAUTHENTICATION, permissionContext);

                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCount(anyString());
                verify(codeStorageService, never())
                        .increaseIncorrectMfaCodeAttemptsCountAccountCreation(anyString());
                verify(authenticationAttemptsService, never())
                        .createOrIncrementCount(anyString(), anyLong(), any(), any());
                assertTrue(result.isSuccess());
            }
        }
    }

    @Nested
    class NoOpMethods {

        @Test
        void allNoOpMethodsShouldReturnSuccessWithNull() {
            var journeyType = JourneyType.SIGN_IN;
            var context = permissionContext;

            assertTrue(
                    userActionsManager
                            .incorrectEmailAddressReceived(journeyType, context)
                            .isSuccess());
            assertTrue(
                    userActionsManager.sentEmailOtpNotification(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.correctEmailOtpReceived(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.incorrectPasswordReceived(journeyType, context).isSuccess());
            assertTrue(userActionsManager.createdPassword(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.correctPasswordReceived(journeyType, context).isSuccess());
            assertTrue(userActionsManager.passwordReset(journeyType, context).isSuccess());
            assertTrue(userActionsManager.sentSmsOtpNotification(journeyType, context).isSuccess());
            assertTrue(userActionsManager.correctSmsOtpReceived(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager
                            .incorrectAuthAppOtpReceived(journeyType, context)
                            .isSuccess());
            assertTrue(
                    userActionsManager.correctAuthAppOtpReceived(journeyType, context).isSuccess());
        }
    }
}
