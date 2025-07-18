package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.RecordError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

public interface UserPermissions {
    public Result<DecisionError, Decision> canUserVerifyMfaOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<RecordError, Void> recordIncorrectMfaOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    public Result<RecordError, Void> recordCorrectMfaOtpReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}
