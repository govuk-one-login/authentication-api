package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.time.Instant;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class PermissionDecisionManager implements PermissionDecisions {
    private static final Logger LOG = LogManager.getLogger(PermissionDecisionManager.class);

    private final CodeStorageService codeStorageService;
    private final ConfigurationService configurationService;

    public PermissionDecisionManager() {
        this.configurationService = ConfigurationService.getInstance();
        var redis = new RedisConnectionService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
    }

    public PermissionDecisionManager(
            CodeStorageService codeStorageService, ConfigurationService configurationService) {
        this.codeStorageService = codeStorageService;
        this.configurationService = configurationService;
    }

    @Override
    public Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        if (journeyType == JourneyType.PASSWORD_RESET) {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestCount = userPermissionContext.authSessionItem().getPasswordResetCount();
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

            // Check Redis block first - use different ForbiddenReason instead of -1
            if (codeStorageService.isBlockedForEmail(
                    userPermissionContext.emailAddress(), codeRequestBlockedKeyPrefix)) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST,
                                0, // Use 0 instead of -1
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration())));
            }

            // Check if count will reach limit after increment
            if (codeRequestCount >= configurationService.getCodeMaxRetries() - 1) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                codeRequestCount,
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration())));
            }

            return Result.success(new Decision.Permitted(codeRequestCount));
        }

        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canVerifyEmailOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        if (journeyType == JourneyType.PASSWORD_RESET) {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

            if (codeStorageService.isBlockedForEmail(
                    userPermissionContext.emailAddress(), codeAttemptsBlockedKeyPrefix)) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                                0,
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration())));
            }
        }

        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canReceivePassword(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {

        if (userPermissionContext == null || userPermissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (journeyType == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            int attemptCount =
                    codeStorageService.getIncorrectPasswordCount(
                            userPermissionContext.emailAddress());

            boolean isBlocked =
                    codeStorageService.isBlockedForEmail(
                            userPermissionContext.emailAddress(),
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET);

            if (isBlocked) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                attemptCount,
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration())));
            }

            return Result.success(new Decision.Permitted(attemptCount));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve from lock details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canVerifySmsOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canVerifyOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return canVerifyAuthAppOtp(journeyType, userPermissionContext);
    }

    @Override
    public Result<DecisionError, Decision> canVerifyAuthAppOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {

        try {
            var ttl =
                    codeStorageService.getMfaCodeBlockTimeToLive(
                            userPermissionContext.emailAddress(),
                            MFAMethodType.AUTH_APP,
                            journeyType);

            if (ttl > 0) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                                0,
                                Instant.ofEpochSecond(ttl)));
            }

            return Result.success(new Decision.Permitted(0));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve from lock details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public Result<DecisionError, Decision> canStartJourney(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }
}
