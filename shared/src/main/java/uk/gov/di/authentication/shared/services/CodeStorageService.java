package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.HashHelper;

import java.util.Optional;

import static java.lang.String.format;

public class CodeStorageService {

    public static final String CODE_REQUEST_BLOCKED_KEY_PREFIX = "code-request-blocked:";
    public static final String CODE_BLOCKED_KEY_PREFIX = "code-blocked:";

    private static final Logger LOG = LogManager.getLogger(CodeStorageService.class);

    private final RedisConnectionService redisConnectionService;
    private final ConfigurationService configurationService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";
    private static final String MFA_KEY_PREFIX = "mfa-code:";

    private static final String MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX =
            "multiple-incorrect-mfa-codes:";
    private static final String CODE_BLOCKED_VALUE = "blocked";
    private static final String RESET_PASSWORD_KEY_PREFIX = "reset-password-code:";
    private static final String MULTIPLE_INCORRECT_PASSWORDS_PREFIX =
            "multiple-incorrect-passwords:";
    private static final String MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX =
            "multiple-incorrect-reauth-email:";
    private static final String MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX =
            "multiple-incorrect-passwords-reauth:";

    private static final String VERIFY_CHANGE_HOW_GET_SECURITY_CODES_KEY_PREFIX =
            "change-how-get-security-codes";

    public CodeStorageService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.redisConnectionService = new RedisConnectionService(configurationService);
    }

    public CodeStorageService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public int getIncorrectMfaCodeAttemptsCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX);
    }

    public int getIncorrectMfaCodeAttemptsCount(String email, MFAMethodType mfaMethodType) {
        var prefix = MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + mfaMethodType.getValue();
        return getCount(email, prefix);
    }

    public void increaseIncorrectMfaCodeAttemptsCount(String email, boolean reducedLockout) {
        increaseCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX, reducedLockout);
    }

    public void increaseIncorrectMfaCodeAttemptsCount(String email, MFAMethodType mfaMethodType) {
        String prefix = MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + mfaMethodType.getValue();
        increaseCount(email, prefix, false);
    }

    public void deleteIncorrectMfaCodeAttemptsCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX);
    }

    public void deleteIncorrectMfaCodeAttemptsCount(String email, MFAMethodType mfaMethodType) {
        String prefix = MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + mfaMethodType.getValue();
        deleteCount(email, prefix);
    }

    public void increaseIncorrectPasswordCount(String email) {
        increaseCount(email, MULTIPLE_INCORRECT_PASSWORDS_PREFIX, false);
    }

    public void increaseIncorrectEmailCount(String email) {
        increaseCount(email, MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX, false);
    }

    public void increaseIncorrectPasswordCountReauthJourney(String email) {
        increaseCount(email, MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX, false);
    }

    private void increaseCount(String email, String prefix, boolean reducedLockout) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;
        Optional<String> count = Optional.ofNullable(redisConnectionService.getValue(key));
        int newCount = count.map(t -> Integer.parseInt(t) + 1).orElse(1);
        long expiry = reducedLockout
                ? configurationService.getReducedLockoutDuration()
                : configurationService.getLockoutDuration();
        LOG.info("lockout expiry: {}", expiry);
        try {
            redisConnectionService.saveWithExpiry(
                    key,
                    String.valueOf(newCount),
                    expiry);
            LOG.info("count increased from: {} to: {}", count, newCount);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public int getIncorrectPasswordCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_PASSWORDS_PREFIX);
    }

    public int getIncorrectEmailCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX);
    }

    public int getIncorrectPasswordCountReauthJourney(String email) {
        return getCount(email, MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX);
    }

    public long getMfaCodeBlockTimeToLive(
            String email, MFAMethodType mfaMethodType, JourneyType journeyType) {
        var codeRequestType = CodeRequestType.getCodeRequestType(mfaMethodType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        return getTTL(email, codeBlockedKeyPrefix);
    }

    private long getTTL(String email, String prefix) {
        return redisConnectionService.getTimeToLive(prefix + HashHelper.hashSha256String(email));
    }

    private int getCount(String email, String prefix) {
        Optional<String> count =
                Optional.ofNullable(
                        redisConnectionService.getValue(
                                prefix + HashHelper.hashSha256String(email)));
        return count.map(Integer::parseInt).orElse(0);
    }

    public void deleteIncorrectPasswordCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_PASSWORDS_PREFIX);
    }

    public void deleteIncorrectEmailCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX);
    }

    public void deleteIncorrectPasswordCountReauthJourney(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX);
    }

    private void deleteCount(String email, String prefix) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;

        try {
            redisConnectionService.deleteValue(key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void saveBlockedForEmail(String email, String prefix, long codeBlockedTime) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;
        try {
            redisConnectionService.saveWithExpiry(key, CODE_BLOCKED_VALUE, codeBlockedTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isBlockedForEmail(String emailAddress, String prefix) {
        return redisConnectionService.getValue(prefix + HashHelper.hashSha256String(emailAddress))
                != null;
    }

    public void saveOtpCode(
            String emailAddress,
            String code,
            long codeExpiryTime,
            NotificationType notificationType) {
        String hashedEmailAddress = HashHelper.hashSha256String(emailAddress);
        String prefix = getPrefixForNotificationType(notificationType);
        String key = prefix + hashedEmailAddress;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getSubjectWithPasswordResetCode(String code) {
        return Optional.ofNullable(
                redisConnectionService.getValue(RESET_PASSWORD_KEY_PREFIX + code));
    }

    public void deleteSubjectWithPasswordResetCode(String code) {
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(RESET_PASSWORD_KEY_PREFIX + code);
        if (numberOfKeysRemoved == 0) {
            LOG.info(format("No key was deleted for code: %s", code));
        }
    }

    public Optional<String> getOtpCode(String emailAddress, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        prefix + HashHelper.hashSha256String(emailAddress)));
    }

    public void deleteOtpCode(String emailAddress, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        prefix + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOG.info(format("No %s key was deleted", prefix));
        }
    }

    public void saveAuthorizationCode(
            String authorizationCode, String clientSessionId, long codeExpiryTime) {
        try {
            redisConnectionService.saveWithExpiry(
                    authorizationCode, clientSessionId, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getPrefixForNotificationType(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_KEY_PREFIX;
            case VERIFY_PHONE_NUMBER:
                return PHONE_NUMBER_KEY_PREFIX;
            case MFA_SMS:
                return MFA_KEY_PREFIX;
            case RESET_PASSWORD_WITH_CODE:
                return RESET_PASSWORD_KEY_PREFIX;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return VERIFY_CHANGE_HOW_GET_SECURITY_CODES_KEY_PREFIX;
        }
        throw new RuntimeException(
                String.format("No redis prefix key configured for %s", notificationType));
    }
}
