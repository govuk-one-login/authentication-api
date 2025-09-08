package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class UserActionsManager implements UserActions {

    private static final Logger LOG = LogManager.getLogger(UserActionsManager.class);

    private final CodeStorageService codeStorageService;
    private final AuthSessionService authSessionService;
    private final ConfigurationService configurationService;

    public UserActionsManager() {
        this.codeStorageService = new CodeStorageService(ConfigurationService.getInstance());
        this.authSessionService = new AuthSessionService(ConfigurationService.getInstance());
        this.configurationService = ConfigurationService.getInstance();
    }

    public UserActionsManager(
            CodeStorageService codeStorageService, AuthSessionService authSessionService) {
        this.codeStorageService = codeStorageService;
        this.authSessionService = authSessionService;
        this.configurationService = ConfigurationService.getInstance();
    }

    @Override
    public Result<TrackingError, Void> incorrectEmailAddressReceived(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {

        if (journeyType == JourneyType.PASSWORD_RESET) {
            var updatedSession =
                    userPermissionContext.authSessionItem().incrementPasswordResetCount();
            authSessionService.updateSession(updatedSession);
            var codeRequestCount = updatedSession.getPasswordResetCount();
            if (codeRequestCount >= configurationService.getCodeMaxRetries()) {
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(
                                RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
                var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
                LOG.info("Setting block for email as user has requested too many OTPs");
                codeStorageService.saveBlockedForEmail(
                        userPermissionContext.emailAddress(),
                        codeRequestBlockedKeyPrefix,
                        configurationService.getLockoutDuration());
                authSessionService.updateSession(updatedSession.resetPasswordResetCount());
            }
        }

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
