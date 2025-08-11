package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class PermissionDecisionManager implements PermissionDecisions {
    private static final Logger LOG = LogManager.getLogger(PermissionDecisionManager.class);

    private final CodeStorageService codeStorageService;

    public PermissionDecisionManager() {
        var configurationService = ConfigurationService.getInstance();
        var redis = new RedisConnectionService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
    }

    public PermissionDecisionManager(CodeStorageService codeStorageService) {
        this.codeStorageService = codeStorageService;
    }

    @Override
    public Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canVerifyEmailOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
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
                                Instant.now().plusSeconds(3600) // placeholder TTL
                                ));
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
