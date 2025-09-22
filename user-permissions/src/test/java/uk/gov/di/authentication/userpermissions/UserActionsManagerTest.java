package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
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
    private final UserPermissionContext userPermissionContext =
            new UserPermissionContext(null, null, EMAIL, authSession);

    @BeforeEach
    void setUp() {
        userActionsManager =
                new UserActionsManager(
                        configurationService,
                        codeStorageService,
                        authSessionService,
                        authenticationAttemptsService);
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(configurationService.getLockoutDuration()).thenReturn(900L);
    }

    @Nested
    class PasswordResetOperations {

        @Test
        void passwordResetShouldDeleteIncorrectPasswordCountAndBlock() {
            var result =
                    userActionsManager.passwordReset(
                            JourneyType.PASSWORD_RESET, userPermissionContext);

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
            var result =
                    userActionsManager.passwordReset(JourneyType.SIGN_IN, userPermissionContext);

            verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
            verify(codeStorageService)
                    .deleteBlockForEmail(
                            EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.SIGN_IN);
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class EmailOtpNotificationOperations {

        @Test
        void sentEmailOtpNotificationShouldIncrementPasswordResetCountForPasswordResetJourney() {
            var result =
                    userActionsManager.sentEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, userPermissionContext);

            verify(authSessionService).updateSession(any(AuthSessionItem.class));
            assertTrue(result.isSuccess());
        }

        @Test
        void sentEmailOtpNotificationShouldBlockUserWhenMaxRetriesReached() {
            var sessionWithMaxCount = authSession;
            for (int i = 0; i < 5; i++) {
                sessionWithMaxCount = sessionWithMaxCount.incrementPasswordResetCount();
            }
            var contextWithMaxCount =
                    new UserPermissionContext(null, null, EMAIL, sessionWithMaxCount);

            var result =
                    userActionsManager.sentEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, contextWithMaxCount);

            var expectedBlockedKey =
                    CODE_REQUEST_BLOCKED_KEY_PREFIX
                            + CodeRequestType.getCodeRequestType(
                                    RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            verify(codeStorageService)
                    .saveBlockedForEmail(eq(EMAIL), eq(expectedBlockedKey), eq(900L));
            verify(authSessionService, times(2)).updateSession(any(AuthSessionItem.class));
            assertTrue(result.isSuccess());
        }

        @Test
        void sentEmailOtpNotificationShouldHandleExactlyMaxRetries() {
            var sessionWithExactMaxCount = authSession;
            for (int i = 0; i < 6; i++) {
                sessionWithExactMaxCount = sessionWithExactMaxCount.incrementPasswordResetCount();
            }
            var contextWithExactMaxCount =
                    new UserPermissionContext(null, null, EMAIL, sessionWithExactMaxCount);

            var result =
                    userActionsManager.sentEmailOtpNotification(
                            JourneyType.PASSWORD_RESET, contextWithExactMaxCount);

            var expectedBlockedKey =
                    CODE_REQUEST_BLOCKED_KEY_PREFIX
                            + CodeRequestType.getCodeRequestType(
                                    RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            verify(codeStorageService)
                    .saveBlockedForEmail(eq(EMAIL), eq(expectedBlockedKey), eq(900L));
            verify(authSessionService, times(2)).updateSession(any(AuthSessionItem.class));
            assertTrue(result.isSuccess());
        }

        @Test
        void sentEmailOtpNotificationShouldNotBlockForNonPasswordResetJourney() {
            var result =
                    userActionsManager.sentEmailOtpNotification(
                            JourneyType.SIGN_IN, userPermissionContext);

            verify(codeStorageService, never())
                    .saveBlockedForEmail(anyString(), anyString(), anyLong());
            assertTrue(result.isSuccess());
        }
    }

    @Nested
    class NoOpMethods {

        @Test
        void allNoOpMethodsShouldReturnSuccessWithNull() {
            var journeyType = JourneyType.SIGN_IN;
            var context = userPermissionContext;

            assertTrue(
                    userActionsManager
                            .incorrectEmailAddressReceived(journeyType, context)
                            .isSuccess());
            assertTrue(
                    userActionsManager.incorrectEmailOtpReceived(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.correctEmailOtpReceived(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.incorrectPasswordReceived(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.correctPasswordReceived(journeyType, context).isSuccess());
            assertTrue(userActionsManager.sentSmsOtpNotification(journeyType, context).isSuccess());
            assertTrue(
                    userActionsManager.incorrectSmsOtpReceived(journeyType, context).isSuccess());
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
