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
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

import java.time.temporal.ChronoUnit;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class UserActionsManager implements UserActions {

    private static final Logger LOG = LogManager.getLogger(UserActionsManager.class);

    private final ConfigurationService configurationService;
    private CodeStorageService codeStorageService;
    private AuthSessionService authSessionService;
    private AuthenticationAttemptsService authenticationAttemptsService;

    public UserActionsManager(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public UserActionsManager(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthSessionService authSessionService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authSessionService = authSessionService;
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
            JourneyType journeyType, PermissionContext permissionContext) {
        if (journeyType == JourneyType.REAUTHENTICATION) {
            try {

                String identifier =
                        permissionContext.internalSubjectId() != null
                                ? permissionContext.internalSubjectId()
                                : permissionContext.rpPairwiseId();
                getAuthenticationAttemptsService()
                        .createOrIncrementCount(
                                identifier,
                                NowHelper.nowPlus(
                                                configurationService.getReauthEnterEmailCountTTL(),
                                                ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond(),
                                JourneyType.REAUTHENTICATION,
                                CountType.ENTER_EMAIL);
            } catch (RuntimeException e) {
                LOG.error(
                        "Failed to store incorrect email count in AuthenticationAttemptsService",
                        e);
                return Result.failure(TrackingError.STORAGE_SERVICE_ERROR);
            }
        }

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> sentEmailOtpNotification(
            JourneyType journeyType, PermissionContext permissionContext) {

        if (journeyType == JourneyType.PASSWORD_RESET) {
            var updatedSession = permissionContext.authSessionItem().incrementPasswordResetCount();
            getAuthSessionService().updateSession(updatedSession);
            var codeRequestCount = updatedSession.getPasswordResetCount();
            if (codeRequestCount >= configurationService.getCodeMaxRetries()) {
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(
                                RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
                var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
                LOG.info("Setting block for email as user has requested too many OTPs");
                getCodeStorageService()
                        .saveBlockedForEmail(
                                permissionContext.emailAddress(),
                                codeRequestBlockedKeyPrefix,
                                configurationService.getLockoutDuration());
                getAuthSessionService().updateSession(updatedSession.resetPasswordResetCount());
            }
        }

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectEmailOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctEmailOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectPasswordReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        if (journeyType.equals(JourneyType.REAUTHENTICATION)) {
            getAuthenticationAttemptsService()
                    .createOrIncrementCount(
                            permissionContext.internalSubjectId(),
                            NowHelper.nowPlus(
                                            configurationService.getReauthEnterPasswordCountTTL(),
                                            ChronoUnit.SECONDS)
                                    .toInstant()
                                    .getEpochSecond(),
                            journeyType,
                            CountType.ENTER_PASSWORD);
        } else {
            var updatedCount =
                    getCodeStorageService()
                            .increaseIncorrectPasswordCount(permissionContext.emailAddress());
            if (updatedCount >= configurationService.getMaxPasswordRetries()) {
                LOG.info("User has now exceeded max password retries, setting block");
                getCodeStorageService()
                        .saveBlockedForEmail(
                                permissionContext.emailAddress(),
                                CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                        + JourneyType.PASSWORD_RESET,
                                configurationService.getLockoutDuration());

                getCodeStorageService()
                        .deleteIncorrectPasswordCount(permissionContext.emailAddress());
            }
        }

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, PermissionContext permissionContext) {
        getCodeStorageService().deleteIncorrectPasswordCount(permissionContext.emailAddress());

        String codeBlockedKeyPrefix = CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + journeyType;

        getCodeStorageService()
                .deleteBlockForEmail(permissionContext.emailAddress(), codeBlockedKeyPrefix);

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        return Result.success(null);
    }

    private AuthenticationAttemptsService getAuthenticationAttemptsService() {
        if (authenticationAttemptsService == null) {
            authenticationAttemptsService = new AuthenticationAttemptsService(configurationService);
        }
        return authenticationAttemptsService;
    }

    private CodeStorageService getCodeStorageService() {
        if (codeStorageService == null) {
            codeStorageService = new CodeStorageService(configurationService);
        }
        return codeStorageService;
    }

    private AuthSessionService getAuthSessionService() {
        if (authSessionService == null) {
            authSessionService = new AuthSessionService(configurationService);
        }
        return authSessionService;
    }
}
