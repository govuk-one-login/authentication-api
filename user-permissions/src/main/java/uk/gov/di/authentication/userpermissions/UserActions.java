package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

/**
 * Interface for tracking user authentication actions.
 *
 * <p>This interface provides methods to record various user authentication activities such as email
 * verification, password submission, and OTP verification.
 */
public interface UserActions {
    /**
     * Records that an incorrect email address was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectEmailAddressReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an email OTP notification was sent to the user.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an incorrect email OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectEmailOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that a correct email OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctEmailOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an incorrect password was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectPasswordReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that a correct password was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that a password was reset.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an SMS OTP notification was sent to the user.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an incorrect SMS OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that a correct SMS OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that an incorrect authenticator app OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);

    /**
     * Records that a correct authenticator app OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param permissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext);
}
