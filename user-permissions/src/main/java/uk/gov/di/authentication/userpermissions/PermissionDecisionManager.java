package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.LockoutInformation;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

public class PermissionDecisionManager implements UserPermissions {

    private final CodeStorageService codeStorageService;

    public PermissionDecisionManager() {
        var configurationService = ConfigurationService.getInstance();
        var redis = new RedisConnectionService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
    }

    public PermissionDecisionManager(CodeStorageService codeStorageService) {
        var configurationService = ConfigurationService.getInstance();
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
        try {
            // Validate input parameters
            if (userPermissionContext == null || userPermissionContext.emailAddress() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            if (journeyType == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            // Check if user is blocked for password operations
            boolean isBlocked =
                    codeStorageService.isBlockedForEmail(
                            userPermissionContext.emailAddress(),
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET);

            if (isBlocked) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                0,
                                Instant.now().plusSeconds(3600) // placeholder TTL
                                ));
            }

            return Result.success(new Decision.Permitted(0));
        } catch (Exception e) {
            // Catch all exceptions from storage service calls
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
    public Result<DecisionError, Decision> canVerifyAuthAppOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canStartJourney(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, List<LockoutInformation>> getActiveAuthAppLockouts(
            UserPermissionContext userPermissionContext) {
        return Result.success(
                Stream.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA)
                        .map(
                                journeyType -> {
                                    var ttl =
                                            codeStorageService.getMfaCodeBlockTimeToLive(
                                                    userPermissionContext.emailAddress(),
                                                    MFAMethodType.AUTH_APP,
                                                    journeyType);
                                    return new LockoutInformation(
                                            "codeBlock", MFAMethodType.AUTH_APP, ttl, journeyType);
                                })
                        .filter(info -> info.lockTTL() > 0)
                        .toList());
    }
}
