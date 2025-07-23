package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class UserActionsTest {

    private static final UserPermissionContext CONTEXT = mock(UserPermissionContext.class);
    private static final JourneyType JOURNEY_TYPE = JourneyType.SIGN_IN;

    /**
     * This is a simple test to demonstrate how to test implementations of the UserActions
     * interface. In a real implementation, you would create a concrete implementation of
     * UserActions and test it.
     */
    @Test
    void demonstrateHowToTestUserActionsImplementation() {
        // Given
        UserActions userActions = new TestUserActions();

        // When
        Result<TrackingError, Void> result =
                userActions.incorrectEmailAddressReceived(JOURNEY_TYPE, CONTEXT);

        // Then
        assertTrue(result.isSuccess());
    }

    /** Simple implementation of UserActions for testing purposes. */
    private static class TestUserActions implements UserActions {
        @Override
        public Result<TrackingError, Void> incorrectEmailAddressReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> sentEmailOtpNotification(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> incorrectEmailOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> correctEmailOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> incorrectPasswordReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> correctPasswordReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> passwordReset(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> sentSmsOtpNotification(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> incorrectSmsOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> correctSmsOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> incorrectAuthAppOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }

        @Override
        public Result<TrackingError, Void> correctAuthAppOtpReceived(
                JourneyType journeyType, UserPermissionContext userPermissionContext) {
            return Result.success(null);
        }
    }
}
