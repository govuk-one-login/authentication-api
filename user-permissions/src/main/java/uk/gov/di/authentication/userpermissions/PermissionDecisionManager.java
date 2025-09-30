package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
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
    private AuthenticationAttemptsService authenticationAttemptsService;

    public PermissionDecisionManager(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.codeStorageService =
                new CodeStorageService(
                        configurationService, new RedisConnectionService(configurationService));
    }

    public PermissionDecisionManager(
            ConfigurationService configurationService, CodeStorageService codeStorageService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
    }

    public PermissionDecisionManager(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthenticationAttemptsService authenticationAttemptsService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authenticationAttemptsService = authenticationAttemptsService;
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
                                        .plusSeconds(configurationService.getLockoutDuration()),
                                false));
            }

            // Check if count will reach limit after increment
            if (codeRequestCount >= configurationService.getCodeMaxRetries() - 1) {
                boolean isFirstTime =
                        (codeRequestCount == configurationService.getCodeMaxRetries() - 1);
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                codeRequestCount,
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration()),
                                isFirstTime));
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
                                        .plusSeconds(configurationService.getLockoutDuration()),
                                false));
            }
        }

        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canReceivePassword(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {

        if (journeyType == null || userPermissionContext == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (userPermissionContext.internalSubjectId() == null
                    || userPermissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    userPermissionContext.internalSubjectId(),
                    userPermissionContext.rpPairwiseId(),
                    CountType.ENTER_PASSWORD);
        }

        if (userPermissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            boolean isBlocked =
                    codeStorageService.isBlockedForEmail(
                            userPermissionContext.emailAddress(),
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET);

            int attemptCount =
                    isBlocked
                            ? configurationService.getMaxPasswordRetries()
                            : codeStorageService.getIncorrectPasswordCount(
                                    userPermissionContext.emailAddress());

            if (isBlocked) {
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                attemptCount,
                                Instant.now()
                                        .plusSeconds(configurationService.getLockoutDuration()),
                                false));
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
        if (userPermissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            CodeRequestType.SupportedCodeType.MFA, journeyType);
            long ttl =
                    codeStorageService.getTTL(
                            userPermissionContext.emailAddress(),
                            CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        codeStorageService.getTTL(
                                userPermissionContext.emailAddress(),
                                CODE_REQUEST_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType);
                ttl = Math.max(ttl, deprecatedTtl);
            }

            if (ttl > 0) {
                LOG.info("User is blocked from requesting any OTP codes");
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                configurationService.getCodeMaxRetries(),
                                Instant.ofEpochSecond(ttl),
                                false));
            }

            return Result.success(new Decision.Permitted(0));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve MFA code request block details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public Result<DecisionError, Decision> canVerifyMfaOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        if (userPermissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            CodeRequestType.SupportedCodeType.MFA, journeyType);
            long ttl =
                    codeStorageService.getTTL(
                            userPermissionContext.emailAddress(),
                            CODE_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        codeStorageService.getTTL(
                                userPermissionContext.emailAddress(),
                                CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType);
                ttl = Math.max(ttl, deprecatedTtl);
            }

            if (ttl > 0) {
                LOG.info("User is blocked from entering any OTP codes");
                return Result.success(
                        new Decision.TemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                                configurationService.getCodeMaxRetries(),
                                Instant.ofEpochSecond(ttl),
                                false));
            }

            return Result.success(new Decision.Permitted(0));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve MFA code block details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public Result<DecisionError, Decision> canStartJourney(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return Result.success(new Decision.Permitted(0));
    }

    private AuthenticationAttemptsService getAuthenticationAttemptsService() {
        if (authenticationAttemptsService == null) {
            authenticationAttemptsService = new AuthenticationAttemptsService(configurationService);
        }
        return authenticationAttemptsService;
    }

    private Result<DecisionError, Decision> checkForAnyReauthLockout(
            String internalSubjectId, String rpPairwiseId, CountType primaryCountCheck) {

        var reauthCounts =
                getAuthenticationAttemptsService()
                        .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                internalSubjectId, rpPairwiseId, JourneyType.REAUTHENTICATION);

        var exceedingCounts =
                ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                        reauthCounts, configurationService);

        if (!exceedingCounts.isEmpty()) {
            CountType exceededType = exceedingCounts.get(0);

            return Result.success(
                    new Decision.TemporarilyLockedOut(
                            switch (exceededType) {
                                case ENTER_EMAIL -> ForbiddenReason
                                        .EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT;
                                case ENTER_EMAIL_CODE -> ForbiddenReason
                                        .EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT;
                                case ENTER_PASSWORD -> ForbiddenReason
                                        .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT;
                                case ENTER_MFA_CODE,
                                        ENTER_SMS_CODE,
                                        ENTER_AUTH_APP_CODE -> ForbiddenReason
                                        .EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT;
                            },
                            reauthCounts.getOrDefault(exceededType, 0),
                            Instant.now().plusSeconds(configurationService.getLockoutDuration()),
                            false));
        }

        return Result.success(
                new Decision.Permitted(reauthCounts.getOrDefault(primaryCountCheck, 0)));
    }
}
