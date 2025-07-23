package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class UserPermissionsTest {

    private static final UserPermissionContext CONTEXT = mock(UserPermissionContext.class);
    private static final JourneyType JOURNEY_TYPE = JourneyType.SIGN_IN;

    /**
     * This is a simple test to demonstrate how to test implementations of the UserPermissions
     * interface. In a real implementation, you would create a concrete implementation of
     * UserPermissions and test it.
     */
    @Test
    void demonstrateHowToTestUserPermissionsImplementation() {
        // Given
        UserPermissions userPermissions = new TestUserPermissions();

        // When
        Result<DecisionError, Decision> result =
                userPermissions.canReceiveEmailAddress(JOURNEY_TYPE, CONTEXT);

        // Then
        assertTrue(result.isSuccess());
        assertEquals(0, result.getSuccess().attemptCount());
    }

    /** Simple implementation of UserPermissions for testing purposes. */
    private static class TestUserPermissions implements UserPermissions {
        @Override
        public Result<DecisionError, Decision> canReceiveEmailAddress(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canSendEmailOtpNotification(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canVerifyEmailOtp(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canReceivePassword(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canSendSmsOtpNotification(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canVerifySmsOtp(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canVerifyAuthAppOtp(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(new Decision.Permitted(0));
        }

        @Override
        public Result<DecisionError, Decision> canLogin(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return canReceivePassword(journeyType, userPermissionContext);
        }
    }
}
