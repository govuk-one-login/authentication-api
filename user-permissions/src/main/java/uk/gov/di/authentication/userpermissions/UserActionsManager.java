package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CodeRequestType.SupportedCodeType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.entity.InMemoryLockoutStateHolder;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

import java.time.temporal.ChronoUnit;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
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
            if (updatedSession.getPasswordResetCount()
                    >= configurationService.getCodeMaxRetries()) {
                blockAndResetForEmail(
                        permissionContext.emailAddress(),
                        RESET_PASSWORD_WITH_CODE,
                        journeyType,
                        updatedSession.resetPasswordResetCount());
            }
            return Result.success(null);
        }

        var notificationType =
                switch (journeyType) {
                    case REGISTRATION -> VERIFY_EMAIL;
                    case ACCOUNT_RECOVERY -> VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
                    default -> null;
                };

        if (notificationType == null) {
            return Result.success(null);
        }

        var updatedSession =
                permissionContext
                        .authSessionItem()
                        .incrementCodeRequestCount(notificationType, journeyType);
        getAuthSessionService().updateSession(updatedSession);

        if (updatedSession.getCodeRequestCount(notificationType, journeyType)
                >= configurationService.getCodeMaxRetries()) {
            blockAndResetForEmail(
                    permissionContext.emailAddress(),
                    notificationType,
                    journeyType,
                    updatedSession.resetCodeRequestCount(notificationType, journeyType));
        }

        return Result.success(null);
    }

    private void blockAndResetForEmail(
            String email,
            NotificationType notificationType,
            JourneyType journeyType,
            AuthSessionItem resetSession) {
        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        LOG.info("Setting block for email as user has requested too many OTPs");
        getCodeStorageService()
                .saveBlockedForEmail(
                        email,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType,
                        configurationService.getLockoutDuration());
        getAuthSessionService().updateSession(resetSession);
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
    public Result<TrackingError, Void> createdPassword(
            JourneyType journeyType, PermissionContext permissionContext) {
        var updatedSession = permissionContext.authSessionItem().withHasVerifiedPassword(true);
        getAuthSessionService().updateSession(updatedSession);
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctPasswordReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        var updatedSession = permissionContext.authSessionItem().withHasVerifiedPassword(true);
        getAuthSessionService().updateSession(updatedSession);
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> passwordReset(
            JourneyType journeyType, PermissionContext permissionContext) {
        getCodeStorageService().deleteIncorrectPasswordCount(permissionContext.emailAddress());

        String codeBlockedKeyPrefix = CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + journeyType;
        getCodeStorageService()
                .deleteBlockForEmail(permissionContext.emailAddress(), codeBlockedKeyPrefix);

        var updatedSession = permissionContext.authSessionItem().withHasVerifiedPassword(true);
        getAuthSessionService().updateSession(updatedSession);

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> sentSmsOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            InMemoryLockoutStateHolder lockoutStateHolder) {
        var codeRequestType =
                CodeRequestType.getCodeRequestType(SupportedCodeType.MFA, journeyType);
        var updatedSession =
                permissionContext.authSessionItem().incrementCodeRequestCount(codeRequestType);
        getAuthSessionService().updateSession(updatedSession);

        var codeRequestCount = updatedSession.getCodeRequestCount(codeRequestType);
        if (codeRequestCount >= configurationService.getCodeMaxRetries()) {
            var blockPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

            boolean shouldRecordBlock =
                    journeyType != JourneyType.REAUTHENTICATION
                            || !configurationService.supportReauthSignoutEnabled();

            if (shouldRecordBlock) {
                LOG.info("Setting block for email as user has requested too many SMS OTPs");
                getCodeStorageService()
                        .saveBlockedForEmail(
                                permissionContext.emailAddress(),
                                blockPrefix,
                                configurationService.getLockoutDuration());
            } else if (lockoutStateHolder != null) {
                lockoutStateHolder.setReauthSmsOtpLimitExceeded();
            }

            getAuthSessionService()
                    .updateSession(updatedSession.resetCodeRequestCount(codeRequestType));
        }

        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        if (journeyType == JourneyType.REAUTHENTICATION) {
            try {
                getAuthenticationAttemptsService()
                        .createOrIncrementCount(
                                permissionContext.internalSubjectId(),
                                NowHelper.nowPlus(
                                                configurationService
                                                        .getReauthEnterSMSCodeCountTTL(),
                                                ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond(),
                                journeyType,
                                CountType.ENTER_MFA_CODE);
            } catch (RuntimeException e) {
                LOG.error(
                        "Failed to store incorrect SMS OTP count in AuthenticationAttemptsService",
                        e);
                return Result.failure(TrackingError.STORAGE_SERVICE_ERROR);
            }
        } else {
            var updatedCount =
                    getCodeStorageService()
                            .increaseIncorrectMfaCodeAttemptsCount(
                                    permissionContext.emailAddress());
            if (updatedCount >= configurationService.getCodeMaxRetries()) {
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(SupportedCodeType.MFA, journeyType);
                LOG.info("Setting block for email as user has exceeded max MFA code retries");

                boolean reducedLockout =
                        journeyType == JourneyType.REGISTRATION
                                || journeyType == JourneyType.ACCOUNT_RECOVERY;
                long blockDuration =
                        reducedLockout
                                ? configurationService.getReducedLockoutDuration()
                                : configurationService.getLockoutDuration();

                getCodeStorageService()
                        .saveBlockedForEmail(
                                permissionContext.emailAddress(),
                                CodeStorageService.CODE_BLOCKED_KEY_PREFIX + codeRequestType,
                                blockDuration);
                getCodeStorageService()
                        .deleteIncorrectMfaCodeAttemptsCount(permissionContext.emailAddress());
            }
        }
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctSmsOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        var updatedSession = permissionContext.authSessionItem().withHasVerifiedMfa(true);
        getAuthSessionService().updateSession(updatedSession);
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> incorrectAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        if (journeyType == JourneyType.REAUTHENTICATION) {
            try {
                getAuthenticationAttemptsService()
                        .createOrIncrementCount(
                                permissionContext.internalSubjectId(),
                                NowHelper.nowPlus(
                                                configurationService
                                                        .getReauthEnterAuthAppCodeCountTTL(),
                                                ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond(),
                                journeyType,
                                CountType.ENTER_MFA_CODE);
            } catch (RuntimeException e) {
                LOG.error(
                        "Failed to store incorrect Auth App OTP count in AuthenticationAttemptsService",
                        e);
                return Result.failure(TrackingError.STORAGE_SERVICE_ERROR);
            }
        } else {
            var updatedCount =
                    getCodeStorageService()
                            .increaseIncorrectMfaCodeAttemptsCount(
                                    permissionContext.emailAddress());
            if (updatedCount >= configurationService.getCodeMaxRetries()) {
                var codeRequestType =
                        CodeRequestType.getCodeRequestType(MFAMethodType.AUTH_APP, journeyType);
                LOG.info("Setting block for email as user has exceeded max MFA code retries");

                boolean reducedLockout =
                        journeyType == JourneyType.REGISTRATION
                                || journeyType == JourneyType.ACCOUNT_RECOVERY;
                long blockDuration =
                        reducedLockout
                                ? configurationService.getReducedLockoutDuration()
                                : configurationService.getLockoutDuration();

                getCodeStorageService()
                        .saveBlockedForEmail(
                                permissionContext.emailAddress(),
                                CodeStorageService.CODE_BLOCKED_KEY_PREFIX + codeRequestType,
                                blockDuration);
                getCodeStorageService()
                        .deleteIncorrectMfaCodeAttemptsCount(permissionContext.emailAddress());
            }
        }
        return Result.success(null);
    }

    @Override
    public Result<TrackingError, Void> correctAuthAppOtpReceived(
            JourneyType journeyType, PermissionContext permissionContext) {
        var updatedSession = permissionContext.authSessionItem().withHasVerifiedMfa(true);
        getAuthSessionService().updateSession(updatedSession);
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
