package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

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
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectEmailAddressReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an email OTP notification was sent to the user.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an incorrect email OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that a correct email OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an incorrect password was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that a correct password was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that a password was reset.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an SMS OTP notification was sent to the user.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an incorrect SMS OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that a correct SMS OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that an incorrect authenticator app OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Records that a correct authenticator app OTP was received.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result indicating success or failure of the tracking operation
     */
    Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}
