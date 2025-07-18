package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

public interface UserPermissions {
    public Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> incorrectEmailAddressReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifyEmailOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> incorrectEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> correctEmailOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSubmitPassword(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> incorrectPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifySmsOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifyAuthAppOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}
