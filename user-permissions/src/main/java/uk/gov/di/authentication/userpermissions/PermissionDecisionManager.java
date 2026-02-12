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
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.IndefinitelyLockedOutData;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.PermittedData;
import uk.gov.di.authentication.userpermissions.entity.ReauthLockedOutData;
import uk.gov.di.authentication.userpermissions.entity.TemporarilyLockedOutData;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

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
            AuthenticationAttemptsService authenticationAttemptsService,
            InternationalSmsSendLimitService internationalSmsSendLimitService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.internationalSmsSendLimitService = internationalSmsSendLimitService;
    }

    @Override
    public <R> Result<DecisionError, R> canReceiveEmailAddress(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<ReauthLockedOutData, R> onReauthLockedOut) {
        if (journeyType == null || permissionContext == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (permissionContext.internalSubjectIds() == null
                    || permissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    permissionContext.internalSubjectIds(),
                    permissionContext.rpPairwiseId(),
                    CountType.ENTER_EMAIL,
                    onPermitted,
                    onReauthLockedOut);
        }

        return Result.success(onPermitted.apply(new PermittedData(0)));
    }

    @Override
    public <R> Result<DecisionError, R> canSendEmailOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut) {
        if (journeyType == JourneyType.PASSWORD_RESET) {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestCount = permissionContext.authSessionItem().getPasswordResetCount();
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

            // Check Redis block first - use different ForbiddenReason instead of -1
            if (getCodeStorageService()
                    .isBlockedForEmail(
                            permissionContext.emailAddress(), codeRequestBlockedKeyPrefix)) {
                return Result.success(
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST,
                                        0,
                                        Instant.now()
                                                .plusSeconds(
                                                        configurationService.getLockoutDuration()),
                                        false)));
            }

            // Check if count will reach limit after increment
            if (codeRequestCount >= configurationService.getCodeMaxRetries() - 1) {
                boolean isFirstTime =
                        (codeRequestCount == configurationService.getCodeMaxRetries() - 1);
                return Result.success(
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                        codeRequestCount,
                                        Instant.now()
                                                .plusSeconds(
                                                        configurationService.getLockoutDuration()),
                                        isFirstTime)));
            }

            return Result.success(onPermitted.apply(new PermittedData(codeRequestCount)));
        }

        return Result.success(onPermitted.apply(new PermittedData(0)));
    }

    @Override
    public <R> Result<DecisionError, R> canVerifyEmailOtp(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut) {
        if (journeyType == JourneyType.PASSWORD_RESET) {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

            if (getCodeStorageService()
                    .isBlockedForEmail(
                            permissionContext.emailAddress(), codeAttemptsBlockedKeyPrefix)) {
                return Result.success(
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason
                                                .EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                                        0,
                                        Instant.now()
                                                .plusSeconds(
                                                        configurationService.getLockoutDuration()),
                                        false)));
            }
        }

        return Result.success(onPermitted.apply(new PermittedData(0)));
    }

    @Override
    public <R> Result<DecisionError, R> canReceivePassword(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut,
            Function<ReauthLockedOutData, R> onReauthLockedOut) {

        if (journeyType == null || permissionContext == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (permissionContext.internalSubjectIds() == null
                    || permissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    permissionContext.internalSubjectIds(),
                    permissionContext.rpPairwiseId(),
                    CountType.ENTER_PASSWORD,
                    onPermitted,
                    onReauthLockedOut);
        }

        if (permissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        return checkForPasswordResetLockout(
                permissionContext.emailAddress(), onPermitted, onTemporarilyLockedOut);
    }

    @Override
    @SuppressWarnings("java:S2789")
    public <R> Result<DecisionError, R> canSendSmsOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut,
            Function<IndefinitelyLockedOutData, R> onIndefinitelyLockedOut) {
        Optional<String> phoneNumberMaybe = permissionContext.e164FormattedPhoneNumber();
        if (permissionContext.emailAddress() == null || phoneNumberMaybe == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        if (phoneNumberMaybe.isPresent()) {
            try {
                var canSendSms =
                        getInternationalSmsSendLimitService().canSendSms(phoneNumberMaybe.get());
                if (!canSendSms) {
                    return Result.success(
                            onIndefinitelyLockedOut.apply(
                                    new IndefinitelyLockedOutData(
                                            ForbiddenReason
                                                    .EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                            configurationService
                                                    .getInternationalSmsNumberSendLimit())));
                }
            } catch (RuntimeException e) {
                LOG.error("Could not retrieve international SMS send limit details.", e);
                return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
            }
        }

        if (journeyType.equals(JourneyType.PASSWORD_RESET)) {
            // We exit early here as there is no suppoerted CodeRequestType for PASSWORD_RESET
            // Which means we do not yet have a counter for that
            return Result.success(onPermitted.apply(new PermittedData(0)));
        }

        try {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            CodeRequestType.SupportedCodeType.MFA, journeyType);
            long ttl =
                    getCodeStorageService()
                            .getTTL(
                                    permissionContext.emailAddress(),
                                    CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
                                        permissionContext.emailAddress(),
                                        CODE_REQUEST_BLOCKED_KEY_PREFIX
                                                + deprecatedCodeRequestType);
                ttl = Math.max(ttl, deprecatedTtl);
            }

            if (ttl > 0) {
                LOG.info("User is blocked from requesting any OTP codes");
                return Result.success(
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                        configurationService.getCodeMaxRetries(),
                                        Instant.ofEpochSecond(ttl),
                                        false)));
            }

            return Result.success(onPermitted.apply(new PermittedData(0)));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve MFA code request block details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public <R> Result<DecisionError, R> canVerifyMfaOtp(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut) {
        if (permissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        try {
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            CodeRequestType.SupportedCodeType.MFA, journeyType);
            long ttl =
                    getCodeStorageService()
                            .getTTL(
                                    permissionContext.emailAddress(),
                                    CODE_BLOCKED_KEY_PREFIX + codeRequestType);

            // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
            var deprecatedCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
                                        permissionContext.emailAddress(),
                                        CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType);
                ttl = Math.max(ttl, deprecatedTtl);
            }

            if (ttl > 0) {
                LOG.info("User is blocked from entering any OTP codes");
                return Result.success(
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                                        configurationService.getCodeMaxRetries(),
                                        Instant.ofEpochSecond(ttl),
                                        false)));
            }

            return Result.success(onPermitted.apply(new PermittedData(0)));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve MFA code block details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public <R> Result<DecisionError, R> canStartJourney(
            JourneyType journeyType,
            PermissionContext permissionContext,
            Function<PermittedData, R> onPermitted,
            Function<ReauthLockedOutData, R> onReauthLockedOut) {
        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (permissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    permissionContext.internalSubjectIds(),
                    permissionContext.rpPairwiseId(),
                    null,
                    onPermitted,
                    onReauthLockedOut);
        }
        return Result.success(onPermitted.apply(new PermittedData(0)));
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
            internationalSmsSendLimitService =
                    new InternationalSmsSendLimitService(configurationService);
        }
        return internationalSmsSendLimitService;
    }

    private <R> Result<DecisionError, R> checkForAnyReauthLockout(
            List<String> internalSubjectIds,
            String rpPairwiseId,
            CountType primaryCountCheck,
            Function<PermittedData, R> onPermitted,
            Function<ReauthLockedOutData, R> onReauthLockedOut) {
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
                    onReauthLockedOut.apply(
                            new ReauthLockedOutData(
                                    reason,
                                    reauthCounts.getOrDefault(exceededType, 0),
                                    Instant.now()
                                            .plusSeconds(configurationService.getLockoutDuration()),
                                    false,
                                    reauthCounts,
                                    exceedingCounts)));
        }

        int count = primaryCountCheck != null ? reauthCounts.getOrDefault(primaryCountCheck, 0) : 0;
        return Result.success(onPermitted.apply(new PermittedData(count)));
    }

    private <R> Result<DecisionError, R> checkForPasswordResetLockout(
            String emailAddress,
            Function<PermittedData, R> onPermitted,
            Function<TemporarilyLockedOutData, R> onTemporarilyLockedOut) {
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
                        onTemporarilyLockedOut.apply(
                                new TemporarilyLockedOutData(
                                        ForbiddenReason
                                                .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                        attemptCount,
                                        Instant.now()
                                                .plusSeconds(
                                                        configurationService.getLockoutDuration()),
                                        false)));
            }

            return Result.success(onPermitted.apply(new PermittedData(attemptCount)));
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
}
