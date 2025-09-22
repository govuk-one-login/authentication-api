package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.time.temporal.ChronoUnit;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class UserActionsManager implements UserActions {

    private static final Logger LOG = LogManager.getLogger(UserActionsManager.class);

    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final AuthSessionService authSessionService;
    private final AuthenticationAttemptsService authenticationAttemptsService;

    public UserActionsManager(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.codeStorageService = new CodeStorageService(configurationService);
        this.authSessionService = new AuthSessionService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public UserActionsManager(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthSessionService authSessionService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authSessionService = authSessionService;
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public UserActionsManager(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthSessionService authSessionService,
            AuthenticationAttemptsService authenticationAttemptsService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authSessionService = authSessionService;
        this.authenticationAttemptsService = authenticationAttemptsService;
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
        if (journeyType.equals(JourneyType.REAUTHENTICATION)) {
            authenticationAttemptsService.createOrIncrementCount(
                    userPermissionContext.internalSubjectId(),
                    NowHelper.nowPlus(
                                    configurationService.getReauthEnterPasswordCountTTL(),
                                    ChronoUnit.SECONDS)
                            .toInstant()
                            .getEpochSecond(),
                    journeyType,
                    CountType.ENTER_PASSWORD);
        } else {
            var updatedCount =
                    codeStorageService.increaseIncorrectPasswordCount(
                            userPermissionContext.emailAddress());
            if (updatedCount >= configurationService.getMaxPasswordRetries()) {
                LOG.info("User has now exceeded max password retries, setting block");
                codeStorageService.saveBlockedForEmail(
                        userPermissionContext.emailAddress(),
                        CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET,
                        configurationService.getLockoutDuration());

                codeStorageService.deleteIncorrectPasswordCount(
                        userPermissionContext.emailAddress());
            }
        }

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
