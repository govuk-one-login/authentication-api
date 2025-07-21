package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

public interface UserActions {
    Result<TrackingError, Void> incorrectEmailAddressReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> incorrectEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> correctEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> incorrectPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}
