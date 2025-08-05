package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

public class UserActionsManager implements UserActions {

    private final CodeStorageService codeStorageService;

    public UserActionsManager(CodeStorageService codeStorageService) {
        this.codeStorageService = codeStorageService;
    }

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
        codeStorageService.deleteIncorrectPasswordCount(userPermissionContext.emailAddress());

        String codeBlockedKeyPrefix = CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + journeyType;

        codeStorageService.deleteBlockForEmail(
                userPermissionContext.emailAddress(), codeBlockedKeyPrefix);

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
