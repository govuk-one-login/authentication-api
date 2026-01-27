package uk.gov.di.authentication.userpermissions.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.PermissionDecisions;
import uk.gov.di.authentication.userpermissions.UserActions;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExampleSmsVerificationHandlerTest {

    private PermissionDecisions permissionDecisions;
    private UserActions userActions;

    private ExampleSmsVerificationHandler handler;
    private static final String CORRECT_OTP = "372615";
    private static final String INCORRECT_OTP = "000000";

    @BeforeEach
    void setUp() {
        permissionDecisions = mock(PermissionDecisions.class);
        userActions = mock(UserActions.class);
        handler = new ExampleSmsVerificationHandler(permissionDecisions, userActions);
    }

    @Test
    void shouldReturnSuccessWhenOtpIsCorrect() {
        // Given
        when(permissionDecisions.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(userActions.correctSmsOtpReceived(any(), any())).thenReturn(Result.success(null));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertEquals("200: Success", result);
        verify(userActions)
                .correctSmsOtpReceived(any(JourneyType.class), any(PermissionContext.class));
    }

    @Test
    void shouldReturnErrorWhenOtpIsIncorrect() {
        // Given
        when(permissionDecisions.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(userActions.incorrectSmsOtpReceived(any(), any())).thenReturn(Result.success(null));

        // When
        String result = handler.handle(INCORRECT_OTP);

        // Then
        assertEquals("400: Incorrect OTP received", result);
        verify(userActions)
                .incorrectSmsOtpReceived(any(JourneyType.class), any(PermissionContext.class));
    }

    @Test
    void shouldReturnLockedOutWhenUserIsTemporarilyLockedOut() {
        // Given
        Instant lockedUntil = Instant.now().plusSeconds(300);
        ForbiddenReason reason = ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT;
        when(permissionDecisions.canVerifyMfaOtp(any(), any()))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(reason, 5, lockedUntil, false)));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertTrue(result.startsWith("403: User is temporarily locked out due to"));
        assertTrue(result.contains(reason.toString()));
    }

    @Test
    void shouldReturnErrorWhenPermissionCheckFails() {
        // Given
        when(permissionDecisions.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.failure(DecisionError.STORAGE_SERVICE_ERROR));

        // When
        String result = handler.handle(CORRECT_OTP);

        // Then
        assertEquals("500: STORAGE_SERVICE_ERROR", result);
    }
}
