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
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class PermissionDecisionManager implements PermissionDecisions {
    private static final Logger LOG = LogManager.getLogger(PermissionDecisionManager.class);

    private final ConfigurationService configurationService;
    private CodeStorageService codeStorageService;
    private AuthenticationAttemptsService authenticationAttemptsService;
    private InternationalSmsSendLimitService internationalSmsSendLimitService;

    public PermissionDecisionManager(ConfigurationService configurationService) {
        this.configurationService = configurationService;
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
        if (journeyType == null || userPermissionContext == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (userPermissionContext.internalSubjectIds() == null
                    || userPermissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    userPermissionContext.internalSubjectIds(),
                    userPermissionContext.rpPairwiseId(),
                    CountType.ENTER_EMAIL);
        }

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
            if (getCodeStorageService()
                    .isBlockedForEmail(
                            userPermissionContext.emailAddress(), codeRequestBlockedKeyPrefix)) {
                return Result.success(
                        createTemporarilyLockedOut(
                                ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST, 0, false));
            }

            // Check if count will reach limit after increment
            if (codeRequestCount >= configurationService.getCodeMaxRetries() - 1) {
                boolean isFirstTime =
                        (codeRequestCount == configurationService.getCodeMaxRetries() - 1);
                return Result.success(
                        createTemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                codeRequestCount,
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

            if (getCodeStorageService()
                    .isBlockedForEmail(
                            userPermissionContext.emailAddress(), codeAttemptsBlockedKeyPrefix)) {
                return Result.success(
                        createTemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                                0,
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
            if (userPermissionContext.internalSubjectIds() == null
                    || userPermissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    userPermissionContext.internalSubjectIds(),
                    userPermissionContext.rpPairwiseId(),
                    CountType.ENTER_PASSWORD);
        }

        if (userPermissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        return checkForPasswordResetLockout(userPermissionContext.emailAddress());
    }

    @Override
    public Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        if (userPermissionContext.emailAddress() == null || userPermissionContext.e164FormattedPhoneNumber() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            var hasReachedInternationalSmsLimit = getInternationalSmsSendLimitService().hasReachedInternationalSmsLimit(userPermissionContext.e164FormattedPhoneNumber());
            if (hasReachedInternationalSmsLimit) {
                return Result.success(
                        new Decision.IndefinitelyLockedOut(
                                ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                configurationService.getInternationalSmsNumberSendLimit()));
            }
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve international SMS send limit details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }

        try {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            CodeRequestType.SupportedCodeType.MFA, journeyType);
            long ttl =
                    getCodeStorageService()
                            .getTTL(
                                    userPermissionContext.emailAddress(),
                                    CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
                                        userPermissionContext.emailAddress(),
                                        CODE_REQUEST_BLOCKED_KEY_PREFIX
                                                + deprecatedCodeRequestType);
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
                    getCodeStorageService()
                            .getTTL(
                                    userPermissionContext.emailAddress(),
                                    CODE_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
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
        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (userPermissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    userPermissionContext.internalSubjectIds(),
                    userPermissionContext.rpPairwiseId(),
                    null);
        }
        return Result.success(new Decision.Permitted(0));
    }

    private AuthenticationAttemptsService getAuthenticationAttemptsService() {
        if (authenticationAttemptsService == null) {
            authenticationAttemptsService = new AuthenticationAttemptsService(configurationService);
        }
        return authenticationAttemptsService;
    }

    private CodeStorageService getCodeStorageService() {
        if (codeStorageService == null) {
            codeStorageService =
                    new CodeStorageService(
                            configurationService, new RedisConnectionService(configurationService));
        }
        return codeStorageService;
    }

    private InternationalSmsSendLimitService getInternationalSmsSendLimitService() {
        if (internationalSmsSendLimitService == null) {
            internationalSmsSendLimitService = new InternationalSmsSendLimitService(configurationService);
        }
        return internationalSmsSendLimitService;
    }

    private Result<DecisionError, Decision> checkForAnyReauthLockout(
            List<String> internalSubjectIds, String rpPairwiseId, CountType primaryCountCheck) {
        List<String> identifiers = new ArrayList<>();
        if (internalSubjectIds != null) {
            identifiers.addAll(internalSubjectIds);
        }
        identifiers.add(rpPairwiseId);

        var reauthCounts =
                getAuthenticationAttemptsService()
                        .getCountsByJourneyForIdentifiers(
                                identifiers, JourneyType.REAUTHENTICATION);

        var exceedingCounts =
                ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                        reauthCounts, configurationService);

        if (!exceedingCounts.isEmpty()) {
            CountType exceededType = exceedingCounts.get(0);
            ForbiddenReason reason = mapCountTypeToForbiddenReason(exceededType);

            return Result.success(
                    new Decision.ReauthLockedOut(
                            reason,
                            reauthCounts.getOrDefault(exceededType, 0),
                            Instant.now().plusSeconds(configurationService.getLockoutDuration()),
                            false,
                            reauthCounts,
                            exceedingCounts));
        }

        int count = primaryCountCheck != null ? reauthCounts.getOrDefault(primaryCountCheck, 0) : 0;
        return Result.success(new Decision.Permitted(count));
    }

    private Result<DecisionError, Decision> checkForPasswordResetLockout(String emailAddress) {
        try {
            // Check for password blocks
            boolean isPasswordBlocked =
                    getCodeStorageService()
                            .isBlockedForEmail(
                                    emailAddress,
                                    CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                            + JourneyType.PASSWORD_RESET);

            int attemptCount =
                    isPasswordBlocked
                            ? configurationService.getMaxPasswordRetries()
                            : getCodeStorageService().getIncorrectPasswordCount(emailAddress);

            if (isPasswordBlocked) {
                return Result.success(
                        createTemporarilyLockedOut(
                                ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                attemptCount,
                                false));
            }

            return Result.success(new Decision.Permitted(attemptCount));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve password reset lock details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    private ForbiddenReason mapCountTypeToForbiddenReason(CountType countType) {
        return switch (countType) {
            case ENTER_EMAIL -> ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT;
            case ENTER_EMAIL_CODE -> ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT;
            case ENTER_PASSWORD -> ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT;
            case ENTER_MFA_CODE, ENTER_SMS_CODE, ENTER_AUTH_APP_CODE -> ForbiddenReason
                    .EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT;
        };
    }

    private Decision.TemporarilyLockedOut createTemporarilyLockedOut(
            ForbiddenReason reason, int attemptCount, boolean isFirstTime) {
        return new Decision.TemporarilyLockedOut(
                reason,
                attemptCount,
                Instant.now().plusSeconds(configurationService.getLockoutDuration()),
                isFirstTime);
    }
}
