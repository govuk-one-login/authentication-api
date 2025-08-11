package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class UserActionsManagerTest {

    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private UserActionsManager userActionsManager;

    private static final String EMAIL = "test@example.com";
    private static final UserPermissionContext USER_PERMISSION_CONTEXT =
            new UserPermissionContext(null, null, EMAIL, null);

    @BeforeEach
    void setUp() {
        userActionsManager = new UserActionsManager(codeStorageService);
    }

    @Test
    void passwordResetShouldDeleteIncorrectPasswordCountAndBlock() {
        var result =
                userActionsManager.passwordReset(
                        JourneyType.PASSWORD_RESET, USER_PERMISSION_CONTEXT);

        verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
        verify(codeStorageService)
                .deleteBlockForEmail(
                        EMAIL,
                        CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                + JourneyType.PASSWORD_RESET);
        assertTrue(result.isSuccess());
    }

    @Test
    void allNoOpMethodsShouldReturnSuccessWithNull() {
        var journeyType = JourneyType.SIGN_IN;
        var context = USER_PERMISSION_CONTEXT;

        assertTrue(
                userActionsManager.incorrectEmailAddressReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.sentEmailOtpNotification(journeyType, context).isSuccess());
        assertTrue(userActionsManager.incorrectEmailOtpReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.correctEmailOtpReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.incorrectPasswordReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.correctPasswordReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.sentSmsOtpNotification(journeyType, context).isSuccess());
        assertTrue(userActionsManager.incorrectSmsOtpReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.correctSmsOtpReceived(journeyType, context).isSuccess());
        assertTrue(
                userActionsManager.incorrectAuthAppOtpReceived(journeyType, context).isSuccess());
        assertTrue(userActionsManager.correctAuthAppOtpReceived(journeyType, context).isSuccess());
    }
}
