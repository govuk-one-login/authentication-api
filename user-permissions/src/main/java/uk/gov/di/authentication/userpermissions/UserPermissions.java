package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

public interface UserPermissions {
    public Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifyEmailOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSubmitPassword(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifySmsOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<DecisionError, Decision> canVerifyAuthAppOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}
