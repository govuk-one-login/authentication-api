package uk.gov.di.authentication.userpermissions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.CodeRequestTypeNotFoundException;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.InMemoryLockoutStateHolder;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
    public Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, PermissionContext permissionContext) {
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
                    CountType.ENTER_EMAIL);
        }

        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, PermissionContext permissionContext) {
        if (permissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        var codeRequestType = getEmailCodeRequestType(journeyType);
        if (codeRequestType == null) {
            return Result.success(new Decision.Permitted(0));
        }

        var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

        if (getCodeStorageService()
                .isBlockedForEmail(permissionContext.emailAddress(), codeRequestBlockedKeyPrefix)) {
            var reason =
                    journeyType == JourneyType.PASSWORD_RESET
                            ? ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST
                            : ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT;
            return Result.success(createTemporarilyLockedOut(reason, 0, false));
        }

        // PASSWORD_RESET has additional count-based check.
        //
        // This exists because ResetPasswordRequestHandler used to do one check of the count
        // and figured out from that if the action is currently blocked, or would be as a
        // result of this invocation. After the lockout refactor the handler calls
        // canSendEmailOtpNotification() BEFORE incrementing the count and this method does
        // the "as is" and "will be" block checks (hence the -1 comparison).
        //
        // This could be refactored to follow the pattern used in MfaHandler where:
        //   1. Handler calls permissionDecisionManager to check if user is already blocked
        //   2. Handler calls userActionsManager to record the action (which increments count
        //      and sets block if limit exceeded)
        //   3. Handler calls permissionDecisionManager again to check if the action caused a block
        //
        // This would simplify the logic here by removing the count-based prediction and making
        // canSendEmailOtpNotification() a pure permission check (no count logic). After this
        // refactoring, the ternary above deciding the error response may also be removed or
        // moved to the handler, though more thought would be required to check this assumption.
        if (journeyType == JourneyType.PASSWORD_RESET) {
            if (permissionContext.authSessionItem() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }
            var codeRequestCount = permissionContext.authSessionItem().getPasswordResetCount();
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
            JourneyType journeyType, PermissionContext permissionContext) {
        if (permissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        var codeRequestType = getEmailCodeRequestType(journeyType);
        if (codeRequestType == null) {
            return Result.success(new Decision.Permitted(0));
        }

        var codeAttemptsBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (getCodeStorageService()
                .isBlockedForEmail(
                        permissionContext.emailAddress(), codeAttemptsBlockedKeyPrefix)) {
            int attemptCount =
                    getCodeStorageService()
                            .getIncorrectMfaCodeAttemptsCount(permissionContext.emailAddress());
            return Result.success(
                    createTemporarilyLockedOut(
                            ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                            attemptCount,
                            false));
        }

        int attemptCount =
                getCodeStorageService()
                        .getIncorrectMfaCodeAttemptsCount(permissionContext.emailAddress());
        return Result.success(new Decision.Permitted(attemptCount));
    }

    @Override
    public Result<DecisionError, Decision> canReceivePassword(
            JourneyType journeyType, PermissionContext permissionContext) {

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
                    CountType.ENTER_PASSWORD);
        }

        if (permissionContext.emailAddress() == null) {
            return Result.failure(DecisionError.INVALID_USER_CONTEXT);
        }

        return checkForPasswordResetLockout(permissionContext.emailAddress());
    }

    @Override
    @SuppressWarnings("java:S2789")
    public Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType,
            PermissionContext permissionContext,
            InMemoryLockoutStateHolder lockoutStateHolder) {
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
                            new Decision.IndefinitelyLockedOut(
                                    ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                    configurationService.getInternationalSmsNumberSendLimit()));
                }
            } catch (RuntimeException e) {
                LOG.error("Could not retrieve international SMS send limit details.", e);
                return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
            }
        }

        if (journeyType.equals(JourneyType.PASSWORD_RESET)) {
            // We exit early here as there is no supported CodeRequestType for PASSWORD_RESET
            // Which means we do not yet have a counter for that
            return Result.success(new Decision.Permitted(0));
        }

        if (journeyType == JourneyType.REAUTHENTICATION
                && lockoutStateHolder != null
                && lockoutStateHolder.isReauthSmsOtpLimitExceeded()) {
            LOG.info("Reauth user exceeded SMS OTP limit (from InMemoryLockoutStateHolder)");
            return Result.success(
                    new Decision.ReauthLockedOut(
                            ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                            configurationService.getCodeMaxRetries(),
                            Instant.now(),
                            false,
                            Map.of(),
                            List.of()));
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
            JourneyType journeyType, PermissionContext permissionContext) {
        if (permissionContext == null) {
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
                    CountType.ENTER_MFA_CODE);
        }

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
            var deprecatedSmsCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.SMS, journeyType);
            if (deprecatedSmsCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
                                        permissionContext.emailAddress(),
                                        CODE_BLOCKED_KEY_PREFIX + deprecatedSmsCodeRequestType);
                ttl = Math.max(ttl, deprecatedTtl);
            }

            var deprecatedAuthAppCodeRequestType =
                    CodeRequestType.getDeprecatedCodeRequestTypeString(
                            MFAMethodType.AUTH_APP, journeyType);
            if (deprecatedAuthAppCodeRequestType != null) {
                long deprecatedTtl =
                        getCodeStorageService()
                                .getTTL(
                                        permissionContext.emailAddress(),
                                        CODE_BLOCKED_KEY_PREFIX + deprecatedAuthAppCodeRequestType);
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

            int attemptCount =
                    getCodeStorageService()
                            .getIncorrectMfaCodeAttemptsCount(permissionContext.emailAddress());
            return Result.success(new Decision.Permitted(attemptCount));
        } catch (RuntimeException e) {
            LOG.error("Could not retrieve MFA code block details.", e);
            return Result.failure(DecisionError.STORAGE_SERVICE_ERROR);
        }
    }

    @Override
    public Result<DecisionError, Decision> canStartJourney(
            JourneyType journeyType, PermissionContext permissionContext) {
        if (journeyType == JourneyType.REAUTHENTICATION) {
            if (permissionContext.rpPairwiseId() == null) {
                return Result.failure(DecisionError.INVALID_USER_CONTEXT);
            }

            return this.checkForAnyReauthLockout(
                    permissionContext.internalSubjectIds(), permissionContext.rpPairwiseId(), null);
        }
        return Result.success(new Decision.Permitted(0));
    }

    @Override
    public boolean canIssueAuthCode(AuthSessionItem authSession) {
        if (!authSession.getHasVerifiedPassword()) {
            LOG.info("Auth code failed to issue due to session not having a verified password");
            return false;
        }

        if (authSession.getRequestedCredentialStrength() == CredentialTrustLevel.MEDIUM_LEVEL) {
            if (!authSession.getHasVerifiedMfa()) {
                LOG.info("Auth code failed to issue due to session not having a verified MFA");
                return false;
            }
        }

        if (authSession
                .getAchievedCredentialStrength()
                .isLowerThan(authSession.getRequestedCredentialStrength())) {
            LOG.info(
                    "Auth code failed to issue due to session not having an achieved credential strength");
            return false;
        }

        return true;
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

    private CodeRequestType getEmailCodeRequestType(JourneyType journeyType) {
        if (journeyType == JourneyType.PASSWORD_RESET) {
            return CodeRequestType.getCodeRequestType(
                    RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
        }
        try {
            return CodeRequestType.getCodeRequestType(
                    CodeRequestType.SupportedCodeType.EMAIL, journeyType);
        } catch (CodeRequestTypeNotFoundException e) {
            return null;
        }
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
