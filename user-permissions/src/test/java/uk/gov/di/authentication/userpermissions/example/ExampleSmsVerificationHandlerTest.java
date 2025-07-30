package uk.gov.di.authentication.userpermissions.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.UserActions;
import uk.gov.di.authentication.userpermissions.UserPermissions;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.lang.reflect.Field;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExampleSmsVerificationHandlerTest {

    private UserPermissions userPermissions;
    private UserActions userActions;

    private ExampleSmsVerificationHandler handler;
    private static final String CORRECT_OTP = "372615";
    private static final String INCORRECT_OTP = "000000";

    @BeforeEach
    void setUp() throws Exception {
        // Create mocks manually instead of using annotations
        userPermissions = mock(UserPermissions.class);
        userActions = mock(UserActions.class);

        handler = new ExampleSmsVerificationHandler();

        // Use reflection to set the mocked dependencies
        Field userPermissionsField =
                ExampleSmsVerificationHandler.class.getDeclaredField("userPermissions");
        userPermissionsField.setAccessible(true);
        userPermissionsField.set(handler, userPermissions);

        Field userActionsField =
                ExampleSmsVerificationHandler.class.getDeclaredField("userActions");
        userActionsField.setAccessible(true);
        userActionsField.set(handler, userActions);
    }

    @Test
    void shouldReturnSuccessWhenOtpIsCorrect() {
        // Given
        when(userPermissions.canVerifySmsOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(userActions.correctSmsOtpReceived(any(), any())).thenReturn(Result.success(null));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertEquals("200: Success", result);
        verify(userActions)
                .correctSmsOtpReceived(any(JourneyType.class), any(UserPermissionContext.class));
    }

    @Test
    void shouldReturnErrorWhenOtpIsIncorrect() {
        // Given
        when(userPermissions.canVerifySmsOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(userActions.incorrectSmsOtpReceived(any(), any())).thenReturn(Result.success(null));

        // When
        String result = handler.handle(INCORRECT_OTP);

        // Then
        assertEquals("400: Incorrect OTP received", result);
        verify(userActions)
                .incorrectSmsOtpReceived(any(JourneyType.class), any(UserPermissionContext.class));
    }

    @Test
    void shouldReturnLockedOutWhenUserIsTemporarilyLockedOut() {
        // Given
        Instant lockedUntil = Instant.now().plusSeconds(300);
        ForbiddenReason reason = ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT;
        when(userPermissions.canVerifySmsOtp(any(), any()))
                .thenReturn(
                        Result.success(new Decision.TemporarilyLockedOut(reason, 5, lockedUntil)));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertTrue(result.startsWith("403: User is temporarily locked out due to"));
        assertTrue(result.contains(reason.toString()));
    }

    @Test
    void shouldReturnErrorWhenPermissionCheckFails() {
        // Given
        when(userPermissions.canVerifySmsOtp(any(), any()))
                .thenReturn(Result.failure(DecisionError.STORAGE_SERVICE_ERROR));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertEquals("500: STORAGE_SERVICE_ERROR", result);
    }
}
